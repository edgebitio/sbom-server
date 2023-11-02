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

pub mod in_toto;
pub mod nsm;
pub mod util;

use hyper::body::Bytes;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use time::OffsetDateTime;

macro_rules! clap_value_enum_display {
    ($type:path) => {
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                use clap::ValueEnum;

                self.to_possible_value()
                    .expect("no skipped variants")
                    .get_name()
                    .fmt(f)
            }
        }
    };
}

pub struct Artifact {
    pub name: String,
    pub contents: Bytes,
    pub format: ArtifactFormat,
}

#[derive(Clone, Copy, serde::Serialize)]
pub enum ArtifactFormat {
    DockerArchive,
    OciArchive,
}

impl ArtifactFormat {
    pub fn as_str(&self) -> &str {
        use ArtifactFormat::*;

        match self {
            DockerArchive => "docker-archive",
            OciArchive => "oci-archive",
        }
    }
}

#[derive(Clone, Copy, clap::Parser, serde::Serialize)]
#[command(version)]
pub struct Config {
    /// Address on which to listen for requests
    #[arg(default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST), long, short)]
    #[serde(skip)]
    pub address: IpAddr,

    /// Port on which to listen for requests
    #[arg(default_value_t = 8080, long, short)]
    #[serde(skip)]
    pub port: u16,

    /// The NSM device to use when generating enclave attestations
    #[arg(default_value_t = Nsm::Real, long, short)]
    #[serde(skip)]
    pub nsm: Nsm,

    /// External executable to use when generating the SPDX-formatted SBOM
    #[arg(default_value_t = SpdxGenerator::SyftBinary, long, short)]
    #[serde(rename = "spdxGenerator")]
    pub spdx: SpdxGenerator,

    /// Enable one-shot mode, where the server only handles a single request
    #[arg(long, short)]
    #[serde(rename = "oneShot")]
    pub one_shot: bool,

    /// Increase the amount of detail in the logs (can be specified multiple times)
    #[clap(long = "verbose", short, action = clap::ArgAction::Count)]
    pub verbosity: u8,
}

#[derive(Clone, Copy, clap::ValueEnum, serde::Serialize)]
pub enum SpdxGenerator {
    SyftBinary,
    SyftDockerContainer,
}
clap_value_enum_display!(SpdxGenerator);

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Nsm {
    Real,
    Mock,
}
clap_value_enum_display!(Nsm);

pub struct SpdxGeneration {
    pub result: String,
    pub generator_version: String,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
}
