// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct ServiceEvent<T: Debug> {
    pub command: String,
    pub args: T,
}
