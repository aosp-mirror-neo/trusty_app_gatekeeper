/*
 * Copyright (C) 2026 The Android Open Source Project
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

//! This module implements the PasswordKeyRetrieval trait for Gatekeeper

use crate::common::{Context, GkResult};
use crate::trusted_hal::new_early_persistent_fs_session;
use bssl_crypto::{
    hkdf::{self, HkdfSha256},
    rand_bytes,
};
use gk_ta::traits::{self, HmacKey, OpaqueOr};
use secure_storage_aidl_wrapper::{Session, OPEN_READ_WRITE};

const PASSWORD_KEY_SECRET_FILE: &str = "TrustyGkPasswordKey_1";
const PASSWORD_KEY_INFO: &[u8] = b"trusty_gk_password_key_v1";
const PASSWORD_KEY_SALT: [u8; 32] = [
    0x82, 0x80, 0xFA, 0xD3, 0xA8, 0x0A, 0x9A, 0x4B, 0xF7, 0xA5, 0x7D, 0x7B, 0xE9, 0xC3, 0xAB, 0x13,
    0x89, 0xDC, 0x7B, 0x46, 0xEE, 0x71, 0x22, 0xB4, 0x5F, 0x4C, 0x3F, 0xE2, 0x40, 0x04, 0x3B, 0x6C,
];
const PASSWORD_KEY_SECRET_LEN: usize = 32;

pub(crate) struct VmPasswordKeyRetrieval {
    session: Session,
}

impl VmPasswordKeyRetrieval {
    pub(crate) fn new() -> GkResult<Self> {
        Ok(Self {
            session: new_early_persistent_fs_session()
                .context("Create Persistent filesystem session")?,
        })
    }

    fn get_or_create_secret(&self) -> GkResult<Vec<u8>> {
        let file = self
            .session
            .open_file(PASSWORD_KEY_SECRET_FILE, &OPEN_READ_WRITE)
            .with_context(|| format!("Open file {PASSWORD_KEY_SECRET_FILE}"))?;

        if file.is_empty().with_context(|| format!("Read file {PASSWORD_KEY_SECRET_FILE}"))? {
            log::info!("No secret found in storage; generating and storing a new one.");
            let mut secret = [0u8; PASSWORD_KEY_SECRET_LEN];
            rand_bytes(&mut secret);
            file.write_all_at(0, &secret)
                .with_context(|| format!("Write to file {PASSWORD_KEY_SECRET_FILE}"))?;
            self.session
                .commit()
                .with_context(|| format!("Commit to file {PASSWORD_KEY_SECRET_FILE}"))?;
            log::info!("Successfully stored new secret to {}", PASSWORD_KEY_SECRET_FILE);
            Ok(secret.to_vec())
        } else {
            let secret =
                file.read_all().with_context(|| format!("Read file {PASSWORD_KEY_SECRET_FILE}"))?;
            if secret.len() != PASSWORD_KEY_SECRET_LEN {
                log::error!(
                    "Read secret from {PASSWORD_KEY_SECRET_FILE} has unexpected size {} bytes, expected {PASSWORD_KEY_SECRET_LEN}",
                    secret.len(),
                );
                return Err(gk_ta::Error::Internal);
            }
            Ok(secret)
        }
    }
}

impl traits::PasswordKeyRetrieval for VmPasswordKeyRetrieval {
    fn key(&self) -> GkResult<OpaqueOr<HmacKey>> {
        let secret = self.get_or_create_secret()?;
        let key: [u8; 32] = HkdfSha256::derive(
            &secret,
            hkdf::Salt::NonEmpty(&PASSWORD_KEY_SALT),
            PASSWORD_KEY_INFO,
        );
        Ok(OpaqueOr::Explicit(HmacKey(key.to_vec())))
    }
}
