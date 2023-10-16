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

use anyhow::{anyhow, Context, Result};
use reqwest::{blocking, StatusCode, Url};
use std::fs::File;
use std::io::Read;
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

fn main() -> Result<()> {
    use clap::Parser;
    use Action::*;
    use RefSpec::*;

    let config = Options::parse();
    let client = Client::new(&config).context("creating upload client")?;
    match config.action {
        Sbom {
            artifact: DockerArchive(path),
            attest,
        } => client.upload_artifact(path, attest),
        Sbom { .. } => Err(anyhow!("artifact schema is not yet implemented")),
    }
    .and_then(|sbom| Ok(println!("{sbom}")))
}

struct Client {
    client: blocking::Client,
    endpoint: Url,
}

impl Client {
    fn new(config: &Options) -> Result<Self> {
        Ok(Client {
            client: blocking::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .build()?,
            endpoint: Url::parse(&format!("http://{}:{}", config.host, config.port))
                .context("parsing URL")?,
        })
    }

    fn upload_artifact<P: AsRef<Path>>(&self, path: P, attest: bool) -> Result<String> {
        let req = self.client.post(
            match attest {
                true => self.endpoint.join("in-toto/spdx"),
                false => self.endpoint.join("spdx"),
            }
            .context("building endpoint URL")?,
        );

        let resp = match path.as_ref() {
            path if path == Path::new("-") => {
                let mut stdin = Vec::new();
                std::io::stdin()
                    .lock()
                    .read_to_end(&mut stdin)
                    .context("reading from stdin")?;
                req.body(stdin)
            }
            path => req.body(File::open(path).context("opening artifact")?),
        }
        .send()
        .context("sending artifact to server")?;

        let status = resp.status();
        let text = resp.text().context("decoding response")?;
        match status {
            StatusCode::OK => Ok(text),
            status => Err(anyhow!(
                "server failed to process request ({status}): {text}"
            )),
        }
    }
}
