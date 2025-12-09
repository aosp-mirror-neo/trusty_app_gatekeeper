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

//! This module implements the AuthKeyManagement trait for Gatekeeper

use super::trusted_hal::new_hw_crypto_key;
use gk_ta::{
    traits::{AuthKeyManagement, HmacKey, OpaqueOr},
    Error,
};
use hwcrypto_thal::HwCryptoHmac;
use log::{error, warn};

/// This struct wraps HwCryptoHmac and implements AuthKeyManagement for Gatekeeper.
#[derive(Debug)]
pub(crate) struct HwCryptoAuthKey {
    inner: HwCryptoHmac,
}

impl HwCryptoAuthKey {
    /// Creates a new `HwCryptoAuthKey` instance.
    pub(crate) fn new() -> Result<Self, Error> {
        let hw_crypto_key = new_hw_crypto_key()?;
        Ok(Self { inner: hw_crypto_key.into() })
    }
}

impl AuthKeyManagement for HwCryptoAuthKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.hmac(data).map_err(|e| {
            error!("HwCryptoAuthKey::sign failed: {:?}", e);
            Error::Internal
        })
    }

    fn key_agreed(&mut self, _key: OpaqueOr<HmacKey>) -> Result<(), Error> {
        warn!(
            "HwCryptoAuthKey::key_agreed: HwCryptoHmac configured;
        using KEYMINT_SHARED_HMAC_KEY for signing."
        );
        Ok(())
    }
}
