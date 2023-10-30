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
