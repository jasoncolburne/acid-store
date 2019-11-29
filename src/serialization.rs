/*
 * Copyright 2019 Wren Powell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use chrono::NaiveDateTime;
use relative_path::{RelativePath, RelativePathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(remote = "NaiveDateTime")]
pub struct SerializableNaiveDateTime {
    #[serde(getter = "NaiveDateTime::timestamp")]
    secs: i64,
    #[serde(getter = "NaiveDateTime::timestamp_subsec_nanos")]
    nsecs: u32,
}

impl From<SerializableNaiveDateTime> for NaiveDateTime {
    fn from(serializable: SerializableNaiveDateTime) -> Self {
        NaiveDateTime::from_timestamp(serializable.secs, serializable.nsecs)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RelativePathBuf")]
pub struct SerializableRelativePathBuf {
    #[serde(getter = "RelativePathBuf::to_string")]
    path: String
}

impl From<SerializableRelativePathBuf> for RelativePathBuf {
    fn from(serializable: SerializableRelativePathBuf) -> Self {
        RelativePathBuf::from(serializable.path)
    }
}