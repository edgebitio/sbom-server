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
use hyper::http::header::{self, HeaderValue};
use hyper::http::{Method, Request, Response};
use hyper::{body, service, Body, StatusCode};
use ignore_result::Ignore;
use sbom_server::{in_toto, nsm::Nsm};
use sbom_server::{Artifact, ArtifactFormat, Config, SpdxGeneration, SpdxGenerator};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::str;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tokio::sync::oneshot;

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
response_handler!(service_unavailable, StatusCode::SERVICE_UNAVAILABLE);

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    let (tx, rx) = oneshot::channel::<()>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let server = hyper::Server::bind(&SocketAddr::from((config.address, config.port)))
        .serve(service::make_service_fn(move |_conn| {
            let tx = tx.clone();
            async move {
                Ok::<_, Infallible>(service::service_fn(move |req| {
                    let tx = tx.clone();
                    async move {
                        if config.one_shot {
                            if let Ok(Some(tx)) = tx.lock().map(|mut tx| tx.take()) {
                                tx.send(()).ignore()
                            } else {
                                return service_unavailable("server is shutting down");
                            }
                        }
                        Service { config }.handle_request(req).await
                    }
                }))
            }
        }))
        .with_graceful_shutdown(async { rx.await.ignore() });

    Ok(server.await?)
}

enum Attestation {
    None,
    InToto,
}

struct Service {
    config: Config,
}

impl Service {
    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        use ArtifactFormat::*;

        let (head, body) = req.into_parts();

        macro_rules! handle_post {
            ($fn:expr, $ctype:expr) => {
                match head.method {
                    Method::POST => match $fn {
                        Ok(bundle) => Ok({
                            let mut resp = Response::new(Body::from(bundle));
                            resp.headers_mut().insert(header::CONTENT_TYPE, $ctype);
                            resp
                        }),
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
        let upload = match head
            .headers
            .get(header::CONTENT_ENCODING)
            .map(AsRef::as_ref)
        {
            Some(b"gzip") => {
                let mut upload = Vec::new();
                match GzDecoder::new(body.reader()).read_to_end(&mut upload) {
                    Ok(_) => upload.into(),
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

        match head.uri.path() {
            "/spdx" => handle_post!(
                self.process(upload, format, Attestation::None),
                HeaderValue::from_static("application/spdx+json")
            ),
            "/in-toto/spdx" => handle_post!(
                self.process(upload, format, Attestation::InToto),
                HeaderValue::from_static("application/vnd.in-toto.bundle")
            ),
            _ => not_found(""),
        }
    }

    fn process(
        &self,
        upload: Bytes,
        format: ArtifactFormat,
        attest: Attestation,
    ) -> Result<String> {
        let artifact = Artifact {
            name: artifact_name(&upload, format).context("determining name of artifact")?,
            contents: upload,
            format,
        };
        let spdx = generate_spdx(&artifact, self.config.spdx).context("generating SBOM")?;
        match attest {
            Attestation::None => Ok(spdx.result),
            Attestation::InToto => {
                use in_toto::envelope;

                let key: SigningKey = SigningKey::generate(&mut rand::rngs::OsRng);
                let attestation = Nsm::new()?.attest(&key).context("attesting key")?;

                in_toto::bundle(&[
                    envelope::provenance(&artifact, &spdx, self.config, &key)?,
                    envelope::spdx(&artifact, &spdx.result, &key)?,
                    envelope::scai(&artifact, &spdx.result, attestation)?,
                ])
                .context("creating in-toto bundle")
            }
        }
    }
}

fn artifact_name(artifact: &Bytes, format: ArtifactFormat) -> Result<String> {
    use ArtifactFormat::*;

    #[derive(serde::Deserialize)]
    struct DockerImageManifest {
        #[serde(rename = "RepoTags")]
        repo_tags: VecDeque<String>,
    }

    #[derive(serde::Deserialize)]
    struct OciImageIndex {
        manifests: VecDeque<OciImageManifest>,
    }

    #[derive(serde::Deserialize)]
    struct OciImageManifest {
        annotations: HashMap<String, String>,
    }

    macro_rules! find_object {
        ($path:literal, $archive:expr) => {{
            let mut entries = $archive.entries().context("reading entries from archive")?;
            loop {
                let file = match entries.next() {
                    Some(entry) => entry.context("reading entry from archive")?,
                    None => break None,
                };

                if matches!(file.path(), Ok(Cow::Borrowed(path)) if path == Path::new($path))
                {
                    break serde_json::from_reader(file).context("deserializing object")?
                }
            }
        }}
    }

    Ok(match format {
        DockerArchive => {
            let mut archive = tar::Archive::new(artifact.as_ref());
            let manifests: Option<VecDeque<DockerImageManifest>> =
                find_object!("manifest.json", archive);
            manifests
                .and_then(|mut ms| ms.pop_front())
                .and_then(|mut m| m.repo_tags.pop_front())
                .unwrap_or("untagged".into())
                + ".tar"
        }
        OciArchive => {
            let mut archive = tar::Archive::new(artifact.as_ref());
            let index: Option<OciImageIndex> = find_object!("index.json", archive);
            index
                .and_then(|mut i| i.manifests.pop_front())
                .and_then(|mut m| m.annotations.remove("org.opencontainers.image.ref.name"))
                .unwrap_or("untagged".into())
                + ".tar"
        }
    })
}

fn generate_spdx(artifact: &Artifact, generator: SpdxGenerator) -> Result<SpdxGeneration> {
    use SpdxGenerator::*;

    let start = OffsetDateTime::now_utc();
    let dir = tempfile::tempdir().context("creating temporary directory")?;
    let archive_path = dir.path().join("archive.tar");
    std::fs::write(&archive_path, &artifact.contents).context("writing artifact")?;

    let archive_path = archive_path.to_string_lossy();
    let dir_path = dir.path().to_string_lossy();
    let format = artifact.format.as_str();
    let name = &artifact.name;
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
    let end = OffsetDateTime::now_utc();

    let version = Vec::from(
        match generator {
            SyftBinary => Command::new("/syft")
                .arg("--version")
                .output()
                .context("running /syft")?,
            SyftDockerContainer => Command::new("docker")
                .arg("run")
                .arg("anchore/syft")
                .arg("--version")
                .output()
                .context("running syft in container")?,
        }
        .stdout
        .strip_prefix(b"syft ")
        .and_then(|s| s.strip_suffix(b"\n"))
        .context("parsing syft version")?,
    );

    if output.status.success() {
        Ok(SpdxGeneration {
            result: str::from_utf8(&output.stdout)
                .map_err(|err| anyhow!("failed to decode stdout: {err}"))?
                .into(),
            generator_version: String::from_utf8(version)?,
            start,
            end,
        })
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
