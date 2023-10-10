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

use anyhow::{anyhow, Result};
use clap::Parser;
use hyper::body::Bytes;
use hyper::http::{Method, Request, Response};
use hyper::{body, service, Body, Server, StatusCode};
use std::convert::Infallible;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::{fmt, str};

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

    match head.uri.path() {
        "/spdx" => match head.method {
            Method::POST => match handle_upload(body, config.spdx) {
                Ok(bundle) => Ok(Response::new(Body::from(bundle))),
                Err(err) => bad_request(err.to_string()),
            },
            _ => method_not_allowed(""),
        },
        _ => not_found(""),
    }
}

fn handle_upload(upload: Bytes, generator: SpdxGenerator) -> Result<String> {
    generate_spdx("", &SourceCode { tarball: upload }, generator)
}

struct SourceCode {
    tarball: Bytes,
}

fn generate_spdx(name: &str, source: &SourceCode, generator: SpdxGenerator) -> Result<String> {
    use SpdxGenerator::*;

    let dir = tempfile::tempdir()?;
    let archive_path = dir.path().join("archive.tar");
    let mut archive = File::create(&archive_path)?;
    archive.write_all(&source.tarball)?;
    archive.sync_all()?;

    let dir_path_str = dir.path().to_string_lossy();
    let output = match generator {
        SyftBinary => Command::new("/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg(format!("docker-archive:{}", archive_path.to_string_lossy()))
            .output(),
        SyftDockerContainer => Command::new("docker")
            .arg("run")
            .arg(format!("--volume={dir_path_str}:{dir_path_str}:ro",))
            .arg(format!("--workdir={dir_path_str}"))
            .arg("anchore/syft")
            .arg("packages")
            .arg(format!("--source-name={name}"))
            .arg("--output=spdx-json")
            .arg("docker-archive:archive.tar")
            .output(),
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
