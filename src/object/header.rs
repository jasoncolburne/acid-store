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

use std::collections::HashMap;
use std::hash::Hash;

use serde::{Deserialize, Serialize};

use super::chunk::Chunk;
use super::object::{Checksum, Object};

/// The header which stores metadata for a repository.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Header<K>
where
    K: Eq + Hash + Clone,
{
    /// A map of chunk hashes to information about those chunks.
    pub chunks: HashMap<Checksum, Chunk>,

    /// A map of object IDs to information about those objects.
    pub objects: HashMap<K, Object>,
}
