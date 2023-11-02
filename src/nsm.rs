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
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use ed25519::pkcs8::EncodePublicKey;
use ed25519::PublicKeyBytes;
use ed25519_dalek::SigningKey;
use serde_bytes::ByteBuf;

pub trait Attest {
    fn attest(&self, key: &SigningKey) -> Result<Vec<u8>>;
}

pub struct Device {
    fd: i32,
}

impl Device {
    pub fn new() -> Result<Self> {
        let fd = match driver::nsm_init() {
            -1 => anyhow::bail!("failed to connect to NSM"),
            fd => fd,
        };

        Ok(Device { fd })
    }
}

impl Attest for Device {
    fn attest(&self, key: &SigningKey) -> Result<Vec<u8>> {
        let req = Request::Attestation {
            nonce: None,
            user_data: None,
            public_key: Some(ByteBuf::from(
                PublicKeyBytes(key.verifying_key().to_bytes())
                    .to_public_key_der()
                    // TODO: once 8f37b603 makes its way into a release of
                    // ed25519, the error mapping can be removed.
                    .map_err(|err| anyhow!(err))
                    .context("deriving DER-encoded public key")?
                    .as_bytes(),
            )),
        };
        match driver::nsm_process_request(self.fd, req) {
            Response::Attestation { document: doc } => Ok(doc),
            Response::Error(err) => Err(anyhow!("nsm request failed: {:?}", err)),
            response => Err(anyhow!("unexpected response from nsm: {:#?}", response)),
        }
    }
}

pub struct Mock {}

impl Attest for Mock {
    fn attest(&self, key: &SigningKey) -> Result<Vec<u8>> {
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use serde_cbor::Value;
        use std::collections::BTreeMap;

        let attestation = AttestationDoc {
            module_id: "Mock NSM".into(),
            digest: Digest::SHA256,
            timestamp: 0,
            pcrs: BTreeMap::from([(0, ByteBuf::from(vec![0; 48]))]),
            certificate: ByteBuf::new(),
            cabundle: Vec::new(),
            public_key: Some(ByteBuf::from(
                key.verifying_key()
                    .to_public_key_der()
                    .map_err(|err| anyhow!("encoding public key: {err}"))?
                    .as_bytes(),
            )),
            user_data: None,
            nonce: None,
        };
        serde_cbor::to_vec(&Value::Array(vec![
            Value::Bytes(
                serde_cbor::to_vec(&Value::Map(BTreeMap::new()))
                    .context("serializing unprotected map")?,
            ),
            Value::Map(BTreeMap::new()),
            Value::Bytes(attestation.to_binary()),
            Value::Bytes(Vec::new()),
        ]))
        .context("serializing COSE Sign1")
    }
}
