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
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use ed25519::pkcs8::EncodePublicKey;
use ed25519::PublicKeyBytes;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_bytes::ByteBuf;

pub struct Nsm {
    fd: i32,
}

impl Nsm {
    pub fn new() -> Result<Self> {
        let fd = match driver::nsm_init() {
            -1 => anyhow::bail!("failed to connect to NSM"),
            fd => fd,
        };

        Ok(Nsm { fd })
    }

    pub fn attest(&self, key: &Ed25519KeyPair) -> Result<Vec<u8>> {
        let pubkey = {
            let mut pk = PublicKeyBytes([0; 32]);
            pk.0.copy_from_slice(key.public_key().as_ref());
            pk
        };
        let req = Request::Attestation {
            nonce: None,
            user_data: None,
            public_key: Some(ByteBuf::from(
                pubkey
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
