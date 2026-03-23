/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Trusty GateKeeper with Trusted HAL.

mod common;
mod filesystem;
mod gatekeeper;
mod hwcrypto_auth;
mod password;
mod trusted_hal;

use crate::gatekeeper::main_loop;

fn log_formatter(record: &log::Record) -> String {
    let line = record.line().unwrap_or(0);
    let file = record.file().unwrap_or("unknown file");
    format!("{}: gk-in-vm:{}:{} {}\n", record.level(), file, line, record.args())
}

fn main() {
    let config = trusty_log::TrustyLoggerConfig::default()
        .with_min_level(trusty_log::get_debug_level!())
        .format(&log_formatter);

    trusty_log::init_with_config(config);
    main_loop().expect("GateKeeper with Trusted HAL TA quits unexpectedly.");
}
