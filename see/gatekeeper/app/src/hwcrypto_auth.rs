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

use crate::common::{Context, GkResult};
use gk_ta::traits::{AuthKeyManagement, HmacKey, OpaqueOr};
use hwcrypto_thal::{HwCryptoHmac, HwCryptoKey};
use log::{debug, warn};

/// This struct wraps HwCryptoHmac and implements AuthKeyManagement for Gatekeeper.
#[derive(Debug)]
pub(crate) struct HwCryptoAuthKey {
    inner: HwCryptoHmac,
}

impl HwCryptoAuthKey {
    /// Creates a new `HwCryptoAuthKey` instance.
    pub(crate) fn new(hw_crypto_key: HwCryptoKey) -> Self {
        Self { inner: hw_crypto_key.into() }
    }
}

impl AuthKeyManagement for HwCryptoAuthKey {
    fn sign(&self, data: &[u8]) -> GkResult<Vec<u8>> {
        debug!("sign auth key");
        self.inner.hmac(data).context("sign auth key")
    }

    fn key_agreed(&mut self, _key: OpaqueOr<HmacKey>) -> GkResult<()> {
        warn!(
            "HwCryptoAuthKey::key_agreed: HwCryptoHmac configured;
             using KEYMINT_SHARED_HMAC_KEY for signing."
        );
        Ok(())
    }
}
