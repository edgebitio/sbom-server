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

use crate::SourceCode;
use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::value::RawValue;
use std::collections::VecDeque;

const MIME_IN_TOTO: &str = "application/vnd.in-toto+json";
const MIME_COSE_SIGN1: &str = "application/cose; cose-type=\"cose-sign1\"";
const SCHEMA_STATEMENT: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_SPDX: &str = "https://spdx.dev/Document/v2.3";
const PREDICATE_SCAI: &str = "https://in-toto.io/attestation/scai/attribute-report/v0.2";

#[derive(serde::Serialize)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    payload_type: &'static str,
    payload: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(serde::Serialize)]
pub struct EnvelopeSignature {
    keyid: Option<String>,
    sig: String,
}

#[derive(serde::Serialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub kind: String,
    pub subject: VecDeque<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Box<RawValue>,
}

#[derive(serde::Serialize)]
pub struct ResourceDescriptor {
    pub name: String,
    pub digest: Digest,
}

#[derive(serde::Serialize)]
pub struct Digest {
    pub sha256: String,
}

impl Envelope {
    fn new<P: serde::Serialize>(payload: P, key: Option<&SigningKey>) -> Result<Self> {
        let payload = serde_json::to_string(&payload).context("serializing payload")?;
        let mut env = Envelope {
            payload_type: MIME_IN_TOTO,
            payload: base64(&payload),
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
                sig: base64(key.sign(pae.as_bytes()).to_bytes()),
            });
        }
        Ok(env)
    }
}

impl ResourceDescriptor {
    fn new<N, C>(name: N, contents: C) -> ResourceDescriptor
    where
        N: AsRef<str>,
        C: AsRef<[u8]>,
    {
        ResourceDescriptor {
            name: name.as_ref().into(),
            digest: Digest {
                sha256: sha256::digest(contents.as_ref()),
            },
        }
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

    pub fn spdx(source: &SourceCode, spdx: &RawValue, key: &SigningKey) -> Result<Envelope> {
        Envelope::new(
            Statement {
                kind: SCHEMA_STATEMENT.into(),
                subject: VecDeque::from([ResourceDescriptor::new(&source.name, &source.tarball)]),
                predicate_type: PREDICATE_SPDX.into(),
                predicate: spdx.to_owned(),
            },
            Some(key),
        )
        .context("creating SPDX envelope")
    }

    pub fn scai<A>(source: &SourceCode, spdx: &RawValue, attestation: A) -> Result<Envelope>
    where
        A: AsRef<[u8]>,
    {
        Envelope::new(
            Statement {
                kind: SCHEMA_STATEMENT.into(),
                subject: VecDeque::from([ResourceDescriptor::new(
                    format!("{}.spdx.json", source.name),
                    spdx.get(),
                )]),
                predicate_type: PREDICATE_SCAI.into(),
                predicate: serde_json::value::to_raw_value(&serde_json::json!({
                    "attributes": [{
                        "attribute": "VALID_ENCLAVE",
                        "evidence": {
                            "name": "aws-enclave-attestation",
                            "content": base64(attestation),
                            "mediaType": MIME_COSE_SIGN1,
                        }
                    }]
                }))
                .context("serializing SCAI Attribute Report")?,
            },
            None,
        )
        .context("creating SCAI envelope")
    }
}

fn base64<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}
