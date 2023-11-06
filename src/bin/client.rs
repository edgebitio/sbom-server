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
use reqwest::{header, StatusCode, Url};
use sbom_server::util;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

        Ok(
            match s
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
            },
        )
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
        Sbom { artifact, attest } => client.upload_artifact(&artifact, attest).await,
    }
    .map(|sbom| println!("{sbom}"))
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

    async fn upload_artifact(&self, artifact: &RefSpec, attest: bool) -> Result<String> {
        use async_compression::tokio::bufread::GzipEncoder;
        use reqwest::Body;
        use tokio::fs::File;
        use tokio::io::BufReader;
        use tokio_util::io::ReaderStream;
        use RefSpec::*;

        let (path, content_type) = match artifact {
            DockerArchive(path) => (path, "application/x-tar; scheme=docker-archive"),
            OciArchive(path) => (path, "application/x-tar; scheme=oci-archive"),
            _ => anyhow::bail!("artifact schema is not yet implemented"),
        };

        let body = if path == Path::new("-") {
            Body::wrap_stream(ReaderStream::new(GzipEncoder::new(BufReader::new(
                tokio::io::stdin(),
            ))))
        } else {
            Body::wrap_stream(ReaderStream::new(GzipEncoder::new(BufReader::new(
                File::open(path).await.context("opening artifact")?,
            ))))
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

        let status = resp.status();
        let text = resp.text().await.context("decoding response")?;
        match status {
            StatusCode::OK => Ok(text),
            status => Err(anyhow!(
                "server failed to process request ({status}): {text}"
            )),
        }
    }
}
