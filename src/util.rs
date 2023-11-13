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

use log::LevelFilter;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub fn init_logging<'a, F>(verbosity: u8, filters: F)
where
    F: IntoIterator<Item = &'a (&'a str, u8)>,
{
    fn level_filter(verbosity: u8) -> LevelFilter {
        match verbosity {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }

    filters
        .into_iter()
        .fold(
            &mut pretty_env_logger::formatted_builder(),
            |builder, (module, offset)| {
                builder.filter_module(module, level_filter(verbosity.saturating_sub(*offset)))
            },
        )
        .filter_level(level_filter(verbosity))
        .format_timestamp(None)
        .init()
}

pub struct AsyncReadDigest<R: AsyncRead> {
    inner: R,
    hasher: Arc<Mutex<Sha256>>,
}

impl<R: AsyncRead> AsyncReadDigest<R> {
    pub fn new(inner: R) -> (AsyncReadDigest<R>, Arc<Mutex<Sha256>>) {
        let hasher = Arc::new(Mutex::new(Sha256::new()));
        (
            AsyncReadDigest {
                inner,
                hasher: hasher.clone(),
            },
            hasher,
        )
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AsyncReadDigest<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            self.hasher
                .lock()
                .expect("unable to lock mutex on hasher")
                .update(buf.filled());
        }
        res
    }
}
