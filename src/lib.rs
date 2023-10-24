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

pub mod in_toto;
pub mod nsm;

use hyper::body::Bytes;

pub struct Artifact {
    pub name: String,
    pub contents: Bytes,
    pub format: ArtifactFormat,
}
#[derive(Clone, Copy)]
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
