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
use clap::Parser;
use ed25519_dalek::SigningKey;
use flate2::read::GzDecoder;
use hyper::body::{Buf, Bytes};
use hyper::http::{header, Method, Request, Response};
use hyper::{body, service, Body, Server, StatusCode};
use ignore_result::Ignore;
use sbom_server::{in_toto, nsm::Nsm, SourceCode};
use std::convert::Infallible;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::{fmt, str};
use tokio::sync::oneshot;

#[derive(Clone, Copy, clap::Parser)]
#[command(version)]
struct Options {
    #[arg(default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST), long, short)]
    address: IpAddr,

    #[arg(default_value_t = 8080, long, short)]
    port: u16,

    #[arg(default_value_t = SpdxGenerator::SyftBinary, long, short)]
    spdx: SpdxGenerator,

    #[arg(long, short)]
    one_shot: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum SpdxGenerator {
    SyftBinary,
    SyftDockerContainer,
}

impl fmt::Display for SpdxGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use clap::ValueEnum;

        self.to_possible_value()
            .expect("no skipped variants")
            .get_name()
            .fmt(f)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Options::parse();

    let (tx, rx) = oneshot::channel::<()>();
    let tx = Arc::new(Mutex::new(match config.one_shot {
        true => Some(tx),
        false => None,
    }));
    let server = Server::bind(&SocketAddr::from((config.address, config.port)))
        .serve(service::make_service_fn(move |_conn| {
            let tx = tx.clone();
            async move {
                Ok::<_, Infallible>(service::service_fn(move |req| {
                    let tx = tx.clone();
                    async move {
                        if let Ok(Some(tx)) = tx.lock().map(|mut tx| tx.take()) {
                            tx.send(()).ignore();
                        }
                        handle_request(config, req).await
                    }
                }))
            }
        }))
        .with_graceful_shutdown(async {
            rx.await.ignore();
        });

    Ok(server.await?)
}

async fn handle_request(config: Options, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    use ArtifactFormat::*;

    macro_rules! response_handler {
        ($name:ident, $code:expr) => {
            fn $name<T: Into<Body>>(body: T) -> Result<Response<Body>, Infallible> {
                Ok(Response::builder().status($code).body(body.into()).unwrap())
            }
        };
    }

    response_handler!(not_found, StatusCode::NOT_FOUND);
    response_handler!(method_not_allowed, StatusCode::METHOD_NOT_ALLOWED);
    response_handler!(bad_request, StatusCode::BAD_REQUEST);
    response_handler!(internal_server_error, StatusCode::INTERNAL_SERVER_ERROR);

    let (head, body) = req.into_parts();

    macro_rules! handle_post {
        ($fn:expr) => {
            match head.method {
                Method::POST => match $fn {
                    Ok(bundle) => Ok(Response::new(Body::from(bundle))),
                    Err(err) => bad_request(format!("{err:#}\n")),
                },
                _ => method_not_allowed(""),
            }
        };
    }

    let body = match body::to_bytes(body).await {
        Ok(body) => body,
        Err(err) => return internal_server_error(err.to_string()),
    };
    let tarball = match head
        .headers
        .get(header::CONTENT_ENCODING)
        .map(AsRef::as_ref)
    {
        Some(b"gzip") => {
            let mut tarball = Vec::new();
            match GzDecoder::new(body.reader()).read_to_end(&mut tarball) {
                Ok(_) => tarball.into(),
                Err(err) => return internal_server_error(err.to_string()),
            }
        }
        Some(_) => return bad_request("unrecognized content encoding"),
        None => body,
    };
    let format = match head
        .headers
        .get(header::CONTENT_TYPE)
        .ok_or(bad_request("missing content type"))
        .and_then(|header| match header.as_bytes() {
            b"application/x-tar; scheme=docker-archive" => Ok(DockerArchive),
            b"application/x-tar; scheme=oci-archive" => Ok(OciArchive),
            _ => Err(bad_request("unrecognized content type")),
        }) {
        Ok(format) => format,
        Err(resp) => return resp,
    };

    let spdx = config.spdx;

    match head.uri.path() {
        "/spdx" => handle_post!(handle_upload(tarball, format, spdx, Attestation::None)),
        "/in-toto/spdx" => handle_post!(handle_upload(tarball, format, spdx, Attestation::InToto)),
        _ => not_found(""),
    }
}

enum Attestation {
    None,
    InToto,
}

fn handle_upload(
    upload: Bytes,
    format: ArtifactFormat,
    generator: SpdxGenerator,
    attest: Attestation,
) -> Result<String> {
    let source = SourceCode {
        name: "",
        tarball: upload,
    };

    let spdx = generate_spdx(&source, format, generator).context("generating SBOM")?;
    match attest {
        Attestation::None => Ok(spdx),
        Attestation::InToto => {
            let key: SigningKey = SigningKey::generate(&mut rand::rngs::OsRng);

            in_toto::bundle(&[
                in_toto::spdx_envelope(&source, spdx, &key).context("creating SPDX envelope")?,
                in_toto::scai_envelope(&source, Nsm::new()?.attest(&key).context("attesting key")?)
                    .context("creating SCAI envelope")?,
            ])
            .context("creating in-toto bundle")
        }
    }
}

enum ArtifactFormat {
    DockerArchive,
    OciArchive,
}

impl ArtifactFormat {
    fn as_str(&self) -> &str {
        use ArtifactFormat::*;

        match self {
            DockerArchive => "docker-archive",
            OciArchive => "oci-archive",
        }
    }
}

fn generate_spdx(
    source: &SourceCode,
    format: ArtifactFormat,
    generator: SpdxGenerator,
) -> Result<String> {
    use SpdxGenerator::*;

    let dir = tempfile::tempdir().context("creating temporary directory")?;
    let archive_path = dir.path().join("archive.tar");
    std::fs::write(&archive_path, &source.tarball).context("writing source archive")?;

    let archive_path = archive_path.to_string_lossy();
    let dir_path = dir.path().to_string_lossy();
    let format = format.as_str();
    let name = source.name;
    let output = match generator {
        SyftBinary => Command::new("/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg(format!("{format}:{archive_path}"))
            .output()
            .context("running /syft"),
        SyftDockerContainer => Command::new("docker")
            .arg("run")
            .arg(format!("--volume={dir_path}:{dir_path}:ro",))
            .arg(format!("--workdir={dir_path}"))
            .arg("anchore/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg(format!("{format}:archive.tar"))
            .output()
            .context("running syft in container"),
    }?;

    if output.status.success() {
        Ok(str::from_utf8(&output.stdout)
            .map_err(|err| anyhow!("failed to decode stdout: {err}"))?
            .into())
    } else {
        let stdout = str::from_utf8(&output.stdout)
            .map_err(|err| anyhow!("failed to decode stdout: {err}"))
            .map(|stdout| anyhow!("{stdout}"))?;
        let stderr = str::from_utf8(&output.stderr)
            .map_err(|err| anyhow!("failed to decode stderr: {err}"))
            .map(|stderr| anyhow!("{stderr}"))?;
        Err(anyhow!(
            "failed to run syft ({}):\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        ))
    }
}
