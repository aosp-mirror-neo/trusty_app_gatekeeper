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

use gk_ta::Error;
use hwcrypto_thal::{HwCryptoKey, IHwCryptoKey};
use log::error;
use service_manager::wait_for_interface;

const HW_CRYPTO_KEY_SERVICE_NAME: &str =
    "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";

/// Creates a new HwCryptoKey object which wraps the IHwCrptoKey binder.
pub(crate) fn new_hw_crypto_key() -> Result<HwCryptoKey, Error> {
    let hw_crypto_key_service = wait_for_interface::<dyn IHwCryptoKey>(HW_CRYPTO_KEY_SERVICE_NAME)
        .map_err(|e| {
            error!("GK: Failed to connect to IHwCryptoKey service: {:?}", e);
            Error::Internal
        })?;
    Ok(HwCryptoKey::new(hw_crypto_key_service))
}
