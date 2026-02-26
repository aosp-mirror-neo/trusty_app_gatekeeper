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

//! Implementation of helper functions for creating Trusted HAL structs
//! exposed to Gatekeeper in Security VM.

use crate::common::{Context, GkResult};
use hwcrypto_thal::{HwCryptoKey, IHwCryptoKey};
use log::debug;
use secure_storage_aidl_wrapper::{Availability, Filesystem, ISecureStorage, Integrity, Session};
use service_manager::wait_for_interface;

const HW_CRYPTO_KEY_SERVICE_NAME: &str =
    "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";
const SECURE_STORAGE_SERVICE_NAME: &str =
    "android.hardware.security.see.storage.ISecureStorage/default";

/// Creates a new HwCryptoKey object which wraps the IHwCrptoKey binder.
pub(crate) fn new_hw_crypto_key() -> GkResult<HwCryptoKey> {
    debug!("connecting to {HW_CRYPTO_KEY_SERVICE_NAME}");
    let hw_crypto_key_service = wait_for_interface::<dyn IHwCryptoKey>(HW_CRYPTO_KEY_SERVICE_NAME)
        .context("connect to IHwCryptoKey")?;
    Ok(HwCryptoKey::new(hw_crypto_key_service))
}

/// Creates a new transactional session.
pub(crate) fn new_early_persistent_fs_session() -> GkResult<Session> {
    debug!("connecting to {SECURE_STORAGE_SERVICE_NAME}");
    let storage = wait_for_interface::<dyn ISecureStorage>(SECURE_STORAGE_SERVICE_NAME)
        .context("connect to ISecureStorage service")?;
    const EARLY_ACCESS_PERSISTENT_FS: Filesystem = Filesystem {
        integrity: Integrity::TAMPER_DETECT,
        availability: Availability::BEFORE_USERDATA,
        persistent: true,
    };
    Session::new(&storage, &EARLY_ACCESS_PERSISTENT_FS).context("create tamper-detect session")
}
