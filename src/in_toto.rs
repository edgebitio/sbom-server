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

use crate::{Artifact, Config, SpdxGeneration};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

macro_rules! provenance_base {
    () => {
        concat!(
            "https://github.com/edgebitio/sbom-server/blob/",
            clap::crate_version!(),
            "/docs/spec/"
        )
    };
}

const MIME_IN_TOTO: &str = "application/vnd.in-toto+json";
const MIME_COSE_SIGN1: &str = "application/cose; cose-type=\"cose-sign1\"";

const SCHEMA_STATEMENT: &str = "https://in-toto.io/Statement/v1";

const PREDICATE_PROVENANCE: &str = "https://slsa.dev/provenance/v1";
const PREDICATE_SCAI: &str = "https://in-toto.io/attestation/scai/attribute-report/v0.2";
const PREDICATE_SPDX: &str = "https://spdx.dev/Document/v2.3";

const PROVENANCE_BUILD_TYPE: &str = concat!(provenance_base!(), "attested-sbom.md");
const PROVENANCE_BUILDER_ID: &str = concat!(provenance_base!(), "builder.md");
const PROVENANCE_HARDENED_BUILDER_ID: &str = concat!(provenance_base!(), "hardened-builder.md");

const SCAI_ATTR_EVIDENCE_NAME: &str = "aws-enclave-attestation";
const SCAI_ATTR_NAME: &str = "VALID_ENCLAVE";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Envelope {
    #[serde(skip)]
    name: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EnvelopeSignature {
    pub keyid: Option<String>,
    pub sig: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub kind: String,
    pub subject: VecDeque<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Box<RawValue>,
}

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ResourceDescriptor {
    pub name: String,
    pub digest: Digest,
}

impl ResourceDescriptor {
    pub fn new<N, C>(name: N, contents: C) -> Self
    where
        N: AsRef<str>,
        C: AsRef<[u8]>,
    {
        ResourceDescriptor {
            name: name.as_ref().to_owned(),
            digest: Digest {
                sha256: hex::encode(Sha256::digest(contents.as_ref())),
            },
        }
    }
}

#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Digest {
    pub sha256: String,
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.sha256)
    }
}

impl Envelope {
    fn new<N, P>(name: N, payload: P, key: Option<&SigningKey>) -> Result<Self>
    where
        N: AsRef<str>,
        P: serde::Serialize,
    {
        let payload = serde_json::to_string(&payload).context("serializing payload")?;
        let mut env = Envelope {
            name: name.as_ref().to_string(),
            payload_type: MIME_IN_TOTO.into(),
            payload: base64.encode(&payload),
            signatures: Vec::new(),
        };
        if let Some(key) = key {
            let pae = format!(
                "DSSEv1 {} {} {} {}",
                env.payload_type.len(),
                env.payload_type,
                payload.len(),
                payload
            );
            env.signatures.push(EnvelopeSignature {
                keyid: None,
                sig: base64.encode(key.sign(pae.as_bytes()).to_bytes()),
            });
        }
        Ok(env)
    }

    fn payload_subject(&self) -> Result<ResourceDescriptor> {
        Ok(ResourceDescriptor::new(
            format!("{}-envelope-payload.json", self.name),
            base64
                .decode(&self.payload)
                .context("base64-decoding envelope payload")?,
        ))
    }
}

pub fn bundle(envelopes: &[Envelope]) -> Result<String> {
    Ok(envelopes
        .iter()
        .map(|e| serde_json::to_string(e).context("serializing envelope"))
        .collect::<Result<Vec<String>>>()?
        .join("\n"))
}

pub mod envelope {
    use super::*;

    pub fn provenance(
        artifact: &Artifact,
        gen: &SpdxGeneration,
        env: &Envelope,
        config: Config,
        key: &SigningKey,
    ) -> Result<Envelope> {
        Envelope::new(
            format!("{}.provenance", artifact.name),
            Statement {
                kind: SCHEMA_STATEMENT.into(),
                subject: VecDeque::from([env
                    .payload_subject()
                    .context("getting SPDX payload subject")?]),
                predicate_type: PREDICATE_PROVENANCE.into(),
                predicate: serde_json::value::to_raw_value(&serde_json::json!({
                    "buildDefinition": {
                        "buildType": PROVENANCE_BUILD_TYPE,
                        "externalParameters": {
                            "artifactFormat": artifact.format,
                            "artifact": ResourceDescriptor::new(&artifact.name, &artifact.contents),
                        },
                        "internalParameters": config,
                    },
                    "runDetails": {
                        "builder": {
                            "id": match (config.one_shot, config.verbosity) {
                                (true, 0) => PROVENANCE_HARDENED_BUILDER_ID,
                                _ => PROVENANCE_BUILDER_ID,
                            },
                            "version": {
                                "sbom-server": clap::crate_version!(),
                                "syft": gen.generator_version,
                            },
                        },
                        "metadata": {
                            "invocationId": Uuid::new_v4().hyphenated(),
                            "startedOn": gen.start.format(&Rfc3339)?,
                            "finishedOn": gen.end.format(&Rfc3339)?,
                        },
                    }
                }))
                .context("serializing provenance predicate")?,
            },
            Some(key),
        )
        .context("creating provenance envelope")
    }

    pub fn spdx(artifact: &Artifact, spdx: &RawValue, key: &SigningKey) -> Result<Envelope> {
        Envelope::new(
            format!("{}.spdx", artifact.name),
            Statement {
                kind: SCHEMA_STATEMENT.into(),
                subject: VecDeque::from([ResourceDescriptor::new(
                    &artifact.name,
                    &artifact.contents,
                )]),
                predicate_type: PREDICATE_SPDX.into(),
                predicate: spdx.to_owned(),
            },
            Some(key),
        )
        .context("creating SPDX envelope")
    }

    pub fn scai<A>(artifact: &Artifact, env: &Envelope, attestation: A) -> Result<Envelope>
    where
        A: AsRef<[u8]>,
    {
        Envelope::new(
            format!("{}.scai", artifact.name),
            Statement {
                kind: SCHEMA_STATEMENT.into(),
                subject: VecDeque::from([env
                    .payload_subject()
                    .context("getting SPDX payload subject")?]),
                predicate_type: PREDICATE_SCAI.into(),
                predicate: serde_json::value::to_raw_value(&serde_json::json!({
                    "attributes": [{
                        "attribute": SCAI_ATTR_NAME,
                        "evidence": {
                            "name": SCAI_ATTR_EVIDENCE_NAME,
                            "content": base64.encode(attestation),
                            "mediaType": MIME_COSE_SIGN1,
                        }
                    }]
                }))
                .context("serializing SCAI predicate")?,
            },
            None,
        )
        .context("creating SCAI envelope")
    }
}

pub struct BundleParts {}

impl std::str::FromStr for BundleParts {
    type Err = anyhow::Error;

    fn from_str(response: &str) -> Result<BundleParts> {
        let bundle = response
            .split('\n')
            .map(|json| serde_json::from_str(json).context("deserializing envelope"))
            .collect::<Result<Vec<Envelope>>>()?;

        for envelope in bundle {
            let Envelope {
                payload_type,
                payload,
                ..
            } = envelope;

            if payload_type != MIME_IN_TOTO {
                log::debug!("Ignoring unrecognized envelope type '{payload_type}'");
                continue;
            }

            let Statement {
                kind,
                predicate_type,
                ..
            } = serde_json::from_slice(&base64.decode(payload).context("base64 decoding")?)
                .context("deserializing statement")?;

            if kind != SCHEMA_STATEMENT {
                log::debug!("Ignoring unrecognized statement type '{kind}'");
                continue;
            }

            match predicate_type.as_str() {
                PREDICATE_SCAI => log::trace!("Found SCAI Attribute Report"),
                PREDICATE_SPDX => log::trace!("Found SPDX Document"),
                PREDICATE_PROVENANCE => log::trace!("Found Provenance statement"),
                p_type => log::debug!("Ignoring unrecognized predicate type '{p_type}'"),
            }
        }

        Ok(BundleParts {})
    }
}
