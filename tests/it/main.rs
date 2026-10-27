// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Single integration-test binary. Each file in this directory is a module.
//!
//! Cargo links every file directly under `tests/` as its own executable, which
//! is costly on slow-link platforms and on targets that install and launch each
//! binary separately (e.g. the iOS simulator). Add new integration tests as a
//! module here rather than as a new top-level file in `tests/`.

mod adversarial_decode;
mod compat_test;
mod cose_differential;
mod deterministic_encoding;
mod rfc8949_compliance;
mod test_newtype_hashmap;
mod test_option_handling;
