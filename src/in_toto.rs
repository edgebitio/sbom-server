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
use serde_json::json;
use serde_json::value::Value;

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

pub fn spdx_envelope(source: &SourceCode, spdx: String, key: &SigningKey) -> Result<Envelope> {
    Envelope::new(
        serde_json::json!({
            "_type": SCHEMA_STATEMENT,
            "subject": statement_subject(source.name, &spdx),
            "predicateType": PREDICATE_SPDX,
            "predicate": spdx,
        }),
        Some(key),
    )
}

pub fn scai_envelope<T: AsRef<[u8]>>(source: &SourceCode, attestation: T) -> Result<Envelope> {
    Envelope::new(
        serde_json::json!({
            "_type": SCHEMA_STATEMENT,
            "subject": statement_subject(source.name, &source.tarball),
            "predicateType": PREDICATE_SCAI,
            "predicate": {
                "attributes": [{
                    "attribute": "VALID_ENCLAVE",
                    "evidence": {
                        "name": "aws-enclave-attestation",
                        "content": base64(attestation),
                        "mediaType": MIME_COSE_SIGN1,
                    }
                }]
            }
        }),
        None,
    )
}

pub fn bundle(envelopes: &[Envelope]) -> Result<String> {
    Ok(envelopes
        .iter()
        .map(|e| serde_json::to_string(e).context("serializing envelope"))
        .collect::<Result<Vec<String>>>()?
        .join("\n"))
}

fn statement_subject<C: AsRef<[u8]>>(name: &str, contents: C) -> Value {
    json!([{
        "name": name,
        "digest": {
            "sha256": sha256::digest(contents.as_ref()),
        }
    }])
}

fn base64<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}
