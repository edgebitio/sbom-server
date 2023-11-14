// Copyright 2023 EdgeBit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{anyhow, Context, Result};
use async_compression::tokio::bufread::GzipEncoder;
use reqwest::{header, Body, StatusCode, Url};
use rustls::{server::ParsedCertificate, Certificate, RootCertStore};
use sbom_server::in_toto::BundleParts;
use sbom_server::util::{self, AsyncReadDigest};
use sha2::Digest as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::BufReader;
use tokio_util::io::ReaderStream;

const NITRO_ROOT_CA: &[u8] = include_bytes!("../../nitro-root.der");
const KNOWN_GOOD_PCR0S: &[u8] = include_bytes!("../../known-good-pcr0s.txt");

#[derive(clap::Parser)]
#[command(version)]
struct Options {
    #[command(subcommand)]
    action: Action,

    /// Hostname of the target sbom-server
    #[arg(long, short = 'H', default_value = "localhost")]
    host: String,

    /// Port number of the target sbom-server (requests are always made without TLS/HTTPS)
    #[arg(long, short, default_value_t = 8080)]
    port: u16,

    /// Increase the amount of detail in the logs (can be specified multiple times)
    #[clap(long = "verbose", short, action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(clap::Subcommand)]
enum Action {
    /// Create an SBOM from the given artifact
    ///
    /// The artifact is referenced by <schema>:<name>, for example:
    ///   docker:repo/image:tag
    ///   podman:repo/image:tag
    ///   registry:repo/image:tag
    ///   docker-archive:path/to/image.tar
    ///   oci-archive:path/to/image.tar
    ///   oci-dir:path/to/image
    ///   singularity:path/to/image.sif
    ///   dir:path/to/project
    ///   file:path/to/project/file
    /// To read the artifact from stdin, use - as the name.
    #[command(verbatim_doc_comment)]
    Sbom {
        /// Artifact for which to generate the SBOM
        #[arg(value_parser = RefSpec::parse)]
        artifact: RefSpec,

        /// Wrap the SBOM in an in-toto attestation
        #[arg(long, short)]
        attest: bool,

        /// Verify the authenticity of the response
        #[arg(default_value_t = true, long, short)]
        verify: bool,
    },
}

#[derive(Clone)]
enum RefSpec {
    Docker(String),
    Podman(String),
    Registry(String),
    DockerArchive(PathBuf),
    OciArchive(PathBuf),
    OciDir(PathBuf),
    Singularity(String),
}

impl RefSpec {
    fn parse(s: &str) -> Result<RefSpec> {
        use RefSpec::*;

        let refspec = match s
            .split_once(':')
            .ok_or(anyhow!("malformed artifact refspec"))?
        {
            ("docker", pullspec) => Docker(pullspec.into()),
            ("podman", pullspec) => Podman(pullspec.into()),
            ("registry", pullspec) => Registry(pullspec.into()),
            ("docker-archive", path) => DockerArchive(path.into()),
            ("oci-archive", path) => OciArchive(path.into()),
            ("oci-dir", path) => OciDir(path.into()),
            ("singularity", pullspec) => Singularity(pullspec.into()),
            (schema, _) => anyhow::bail!("unrecognized artifact schema '{schema}'"),
        };
        Ok(refspec)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser;
    use Action::*;

    let config = Options::parse();
    util::init_logging(config.verbosity, &[("reqwest", 1)]);
    log::info!("sbom-server-client: {}", clap::crate_version!());

    let client = Client::new(&config).context("creating upload client")?;
    match config.action {
        Sbom {
            artifact,
            attest,
            verify,
        } => {
            let (resp, digest) = client.upload_artifact(&artifact, attest).await?;
            println!("{resp}");

            if verify && attest {
                client.verify_intoto_sbom(&resp, &digest)?;
            } else if verify {
                log::warn!(
                    "No attestations to verify; use the --attest flag to request attestations"
                )
            }
        }
    }
    Ok(())
}

struct Client {
    client: reqwest::Client,
    endpoint: Url,
}

impl Client {
    fn new(config: &Options) -> Result<Self> {
        Ok(Client {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .build()?,
            endpoint: Url::parse(&format!("http://{}:{}", config.host, config.port))
                .context("parsing URL")?,
        })
    }

    async fn upload_artifact(&self, artifact: &RefSpec, attest: bool) -> Result<(String, String)> {
        use RefSpec::*;

        let (path, content_type) = match artifact {
            DockerArchive(path) => (path, "application/x-tar; scheme=docker-archive"),
            OciArchive(path) => (path, "application/x-tar; scheme=oci-archive"),
            _ => anyhow::bail!("artifact schema is not yet implemented"),
        };

        let (body, hasher) = if path == Path::new("-") {
            let (reader, hasher) = AsyncReadDigest::new(tokio::io::stdin());
            let stream = ReaderStream::new(GzipEncoder::new(BufReader::new(reader)));
            (Body::wrap_stream(stream), hasher)
        } else {
            let artifact = File::open(path).await.context("opening artifact")?;
            let (reader, hasher) = AsyncReadDigest::new(artifact);
            let stream = ReaderStream::new(GzipEncoder::new(BufReader::new(reader)));
            (Body::wrap_stream(stream), hasher)
        };

        log::info!("Sending artifact...");

        let resp = self
            .client
            .post(
                match attest {
                    true => self.endpoint.join("in-toto/spdx"),
                    false => self.endpoint.join("spdx"),
                }
                .context("building endpoint URL")?,
            )
            .header(
                header::USER_AGENT,
                format!("sbom-server-client/{}", clap::crate_version!()),
            )
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_ENCODING, "gzip")
            .body(body)
            .send()
            .await
            .context("sending artifact to server")?;

        log::info!("Receiving response...");

        // The following two calls to expect() won't panic as long as the response above is awaited.
        let hasher = Arc::into_inner(hasher)
            .expect("unable to take hasher from Arc")
            .into_inner()
            .expect("unable to lock mutex on hasher");
        let digest = hex::encode(hasher.finalize().as_slice());

        let status = resp.status();
        let text = resp.text().await.context("decoding response")?;
        match status {
            StatusCode::OK => Ok((text, digest)),
            status => Err(anyhow!(
                "server failed to process request ({status}): {text}"
            )),
        }
    }

    fn verify_intoto_sbom(&self, response: &str, upload_digest: &str) -> Result<()> {
        log::info!("Verifying attestation bundle");

        let parts = BundleParts::from_str(response).context("extracting response")?;

        log::warn!(
            "Subject of SCAI Attribute Report not yet verified to match payload of SPDX envelope"
        );
        log::warn!("Signature on SPDX envelope not yet verified");
        log::warn!("Server is not yet verified to be using hardened configuration");

        let mut root_store = RootCertStore::empty();
        root_store
            .add(&Certificate(NITRO_ROOT_CA.to_vec()))
            .expect("unable to load root certificate");
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(&Certificate(
                parts.enclave_attestation.certificate.to_vec(),
            ))
            .context("parsing certificate in enclave attestation")?,
            &root_store,
            &parts
                .enclave_attestation
                .cabundle
                .iter()
                .map(|bytes| Certificate(bytes.to_vec()))
                .collect::<Vec<Certificate>>(),
            std::time::SystemTime::now(),
        )
        .context("verifying attestation certificate chain")?;
        log::debug!("Verified enclave attestation certificate chain");

        let pcr0 = parts
            .enclave_attestation
            .pcrs
            .get(&0)
            .context("getting PCR0")?;

        if !KNOWN_GOOD_PCR0S.split(|b| b == &b'\n').any(|raw| {
            hex::decode(raw).unwrap_or_else(|err| {
                log::warn!("Failed to parse known-good PCR0 ({err})");
                Vec::new()
            }) == pcr0[..]
        }) {
            anyhow::bail!("unknown enclave image (PCR0: {})", hex::encode(pcr0))
        }
        log::debug!("Verified enclave image is known-good");

        if parts.spdx.subject.digest.sha256 != upload_digest {
            log::debug!(
                "SPDX Document subject digest: {}",
                parts.spdx.subject.digest.sha256
            );
            log::debug!("Uploaded artifact digest: {}", upload_digest);
            anyhow::bail!("SPDX Document doesn't refer to uploaded artifact");
        }
        log::debug!("Verified subject of SPDX Document matches uploaded artifact");

        Ok(())
    }
}
