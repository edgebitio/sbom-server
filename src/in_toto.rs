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
use anyhow::{anyhow, Context, Result};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use ed25519::Signature;
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
            "https://github.com/edgebitio/sbom-server/blob/v",
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
    pub fn pae<P: AsRef<str>>(payload: P) -> String {
        let payload = payload.as_ref();
        format!(
            "DSSEv1 {} {} {} {}",
            MIME_IN_TOTO.len(),
            MIME_IN_TOTO,
            payload.len(),
            payload
        )
    }

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
            let pae = Self::pae(payload);
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
                            "id": match (config.multiple, config.verbosity) {
                                (false, 0) => PROVENANCE_HARDENED_BUILDER_ID,
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

pub struct BundleParts {
    pub enclave_attestation: AttestationDoc,
    pub scai_subject: ResourceDescriptor,
    pub spdx: SpdxBundleParts,
    pub provenance: ProvenanceBundleParts,
}

pub struct SpdxBundleParts {
    pub signature: Signature,
    pub subject: ResourceDescriptor,
    pub payload: String,
}

pub struct ProvenanceBundleParts {
    pub hardened: bool,
    pub payload: String,
    pub signature: Signature,
}

impl std::str::FromStr for BundleParts {
    type Err = anyhow::Error;

    fn from_str(response: &str) -> Result<BundleParts> {
        let bundle = response
            .split('\n')
            .map(|json| serde_json::from_str(json).context("deserializing envelope"))
            .collect::<Result<Vec<Envelope>>>()?;

        let mut provenance = None;
        let mut enclave_attestation = None;
        let mut scai_subject = None;
        let mut spdx = None;
        for envelope in bundle {
            let Envelope {
                payload_type,
                payload,
                signatures,
                ..
            } = envelope;

            if payload_type != MIME_IN_TOTO {
                log::debug!("Ignoring unrecognized envelope type '{payload_type}'");
                continue;
            }

            let Statement {
                kind,
                predicate,
                predicate_type,
                mut subject,
            } = serde_json::from_slice(&base64.decode(payload.clone()).context("base64 decoding")?)
                .context("deserializing statement")?;

            if kind != SCHEMA_STATEMENT {
                log::debug!("Ignoring unrecognized statement type '{kind}'");
                continue;
            }

            macro_rules! envelope_signature {
                ($name:literal) => {
                    signatures
                        .first()
                        .ok_or(anyhow!("no signatures"))
                        .and_then(|envsig| {
                            log::trace!(
                                "Found signature on {} envelope by {}",
                                $name,
                                envsig.keyid.as_ref().unwrap_or(&"unknown key".into())
                            );
                            let bytes = base64
                                .decode(&envsig.sig)
                                .context("base64-decoding signature")?;
                            Signature::from_slice(&bytes)
                                .map_err(|err| anyhow!("parsing signature: {err}"))
                        })
                        .context(anyhow!("getting signature on {} envelope", $name))?
                };
            }
            macro_rules! envelope_payload {
                ($name:literal) => {
                    String::from_utf8(
                        base64
                            .decode(payload)
                            .context(anyhow!("base64-decoding {} envelope payload", $name))?,
                    )
                    .context(anyhow!("utf8-decoding {} envelope payload", $name))?
                };
            }

            match predicate_type.as_str() {
                PREDICATE_SCAI if enclave_attestation.is_some() => {
                    log::debug!("Ignoring additional SCAI Attribute Report");
                }
                PREDICATE_SCAI => {
                    match attestation_from_scai(predicate.get())
                        .context("extracting attestation from SCAI predicate")?
                    {
                        Some(new) => {
                            log::trace!("Found enclave attestation");
                            enclave_attestation = Some(new);
                            scai_subject = subject.pop_front();
                        }
                        None => {
                            log::debug!("No attestation found in SCAI Attribute Report")
                        }
                    }
                }
                PREDICATE_SPDX if spdx.is_some() => {
                    log::debug!("Ignoring additional SPDX Document")
                }
                PREDICATE_SPDX => {
                    log::trace!("Found SPDX statement");

                    spdx = Some(SpdxBundleParts {
                        signature: envelope_signature!("SPDX"),
                        subject: subject
                            .pop_front()
                            .context("SPDX Statement has no subject")?,
                        payload: envelope_payload!("SPDX"),
                    });
                }
                PREDICATE_PROVENANCE if provenance.is_some() => {
                    log::debug!("Ignoring additional Provenance document");
                }
                PREDICATE_PROVENANCE => {
                    log::trace!("Found Provenance statement");

                    #[derive(serde::Deserialize)]
                    struct Provenance {
                        #[serde(rename = "buildDefinition")]
                        build_definition: BuildDefinition,
                    }
                    #[derive(serde::Deserialize)]
                    struct BuildDefinition {
                        #[serde(rename = "internalParameters")]
                        internal_parameters: InternalParameters,
                    }
                    #[derive(serde::Deserialize)]
                    struct InternalParameters {
                        multiple: bool,
                        verbosity: u8,
                    }

                    let Provenance {
                        build_definition:
                            BuildDefinition {
                                internal_parameters: params,
                            },
                    } = serde_json::from_str(predicate.get())
                        .context("parsing Provenance Document")?;

                    provenance = Some(ProvenanceBundleParts {
                        hardened: !params.multiple && params.verbosity == 0,
                        payload: envelope_payload!("Provenance"),
                        signature: envelope_signature!("Provenance"),
                    });
                }
                p_type => log::debug!("Ignoring unrecognized predicate type '{p_type}'"),
            }
        }

        Ok(BundleParts {
            enclave_attestation: enclave_attestation
                .ok_or(anyhow!("no enclave attestation found"))?,
            provenance: provenance.ok_or(anyhow!("no Provenance Document found"))?,
            scai_subject: scai_subject
                .ok_or(anyhow!("no subject found in SCAI Attribute Report"))?,
            spdx: spdx.ok_or(anyhow!("no SPDX Document found"))?,
        })
    }
}

fn attestation_from_scai(predicate: &str) -> Result<Option<AttestationDoc>> {
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ScaiAttributeReport {
        pub attributes: VecDeque<ScaiAttribute>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ScaiAttribute {
        pub attribute: String,
        pub evidence: ScaiAttributeEvidence,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct ScaiAttributeEvidence {
        pub name: String,
        pub content: String,
        #[serde(rename = "mediaType")]
        pub media_type: String,
    }

    serde_json::from_str::<ScaiAttributeReport>(predicate)
        .context("deserializing SCAI predicate")?
        .attributes
        .into_iter()
        .find_map(|attr| {
            let ScaiAttribute {
                attribute,
                evidence:
                    ScaiAttributeEvidence {
                        name,
                        media_type,
                        content,
                    },
            } = attr;

            if attribute != SCAI_ATTR_NAME {
                log::debug!("Ignoring unrecognized SCAI attribute '{attribute}'");
                return None;
            }

            if name != SCAI_ATTR_EVIDENCE_NAME {
                log::debug!("Ignoring unrecognized SCAI attribute evidence '{name}'",);
                return None;
            }

            if media_type != MIME_COSE_SIGN1 {
                log::debug!(
                    "Ignoring unrecognized SCAI attribute evidence media type '{media_type}'",
                );
                return None;
            }

            Some(content)
        })
        .map(|content| {
            AttestationDoc::from_binary(
                &serde_cose::from_slice(
                    &base64
                        .decode(content)
                        .context("base64-decoding SCAI evidence content")?,
                )
                .context("cose-decoding evidence")?
                .payload,
            )
            .map_err(|err| anyhow!("parsing enclave attestation: {err:?}"))
        })
        .transpose()
}
