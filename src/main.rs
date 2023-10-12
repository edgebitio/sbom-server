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
use hyper::body::Bytes;
use hyper::http::{Method, Request, Response};
use hyper::{body, service, Body, Server, StatusCode};
use nsm::Nsm;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::{fmt, str};

mod in_toto;
mod nsm;

pub struct SourceCode<'a> {
    name: &'a str,
    tarball: Bytes,
}

#[derive(Clone, Copy, clap::Parser)]
#[command(version)]
struct Options {
    #[clap(default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST), long, short)]
    address: IpAddr,

    #[clap(default_value_t = 8080, long, short)]
    port: u16,

    #[clap(default_value_t = SpdxGenerator::SyftBinary, long, short)]
    spdx: SpdxGenerator,
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

    let server = Server::bind(&SocketAddr::from((config.address, config.port))).serve(
        service::make_service_fn(|_conn| async move {
            Ok::<_, Infallible>(service::service_fn(move |req| async move {
                handle_request(config, req).await
            }))
        }),
    );

    Ok(server.await?)
}

async fn handle_request(config: Options, req: Request<Body>) -> Result<Response<Body>, Infallible> {
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
    let body = match body::to_bytes(body).await {
        Ok(body) => body,
        Err(err) => return internal_server_error(err.to_string()),
    };

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

    match head.uri.path() {
        "/spdx" => handle_post!(handle_upload(body, config.spdx, Attestation::None)),
        "/in-toto/spdx" => handle_post!(handle_upload(body, config.spdx, Attestation::InToto)),
        _ => not_found(""),
    }
}

enum Attestation {
    None,
    InToto,
}

fn handle_upload(upload: Bytes, generator: SpdxGenerator, attest: Attestation) -> Result<String> {
    let source = SourceCode {
        name: "",
        tarball: upload,
    };

    let spdx = generate_spdx(&source, generator).context("generating SBOM")?;
    match attest {
        Attestation::None => Ok(spdx),
        Attestation::InToto => {
            let key = Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|_| anyhow!("failed to generate key pair"))?
                    .as_ref(),
            )
            .map_err(|_| anyhow!("failed to parse generated key pair"))?;

            in_toto::bundle(&[
                in_toto::spdx_envelope(&source, spdx, &key).context("creating SPDX envelope")?,
                in_toto::scai_envelope(&source, Nsm::new()?.attest(&key).context("attesting key")?)
                    .context("creating SCAI envelope")?,
            ])
            .context("creating in-toto bundle")
        }
    }
}

fn generate_spdx(source: &SourceCode, generator: SpdxGenerator) -> Result<String> {
    use SpdxGenerator::*;

    let dir = tempfile::tempdir().context("creating temporary directory")?;
    let archive_path = dir.path().join("archive.tar");
    std::fs::write(&archive_path, &source.tarball).context("writing source archive")?;

    let dir_path_str = dir.path().to_string_lossy();
    let name = source.name;
    let output = match generator {
        SyftBinary => Command::new("/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg(format!("docker-archive:{}", archive_path.to_string_lossy()))
            .output()
            .context("running /syft"),
        SyftDockerContainer => Command::new("docker")
            .arg("run")
            .arg(format!("--volume={dir_path_str}:{dir_path_str}:ro",))
            .arg(format!("--workdir={dir_path_str}"))
            .arg("anchore/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg("docker-archive:archive.tar")
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
