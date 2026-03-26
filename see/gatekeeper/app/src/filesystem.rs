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

//! This module implements the SecureFilesystem trait for Gatekeeper

use crate::common::{Context, GkResult};
use alloc::{sync::Arc, vec};
use gk_ta::{traits, Error};
use log::debug;
use secure_storage_aidl_wrapper::{Session, OPEN_READ_WRITE};

pub(crate) struct VmSecureFilesystem {
    session: Arc<Session>,
}

impl VmSecureFilesystem {
    pub(crate) fn new(session: Arc<Session>) -> Self {
        Self { session }
    }
}

impl traits::SecureFilesystem for VmSecureFilesystem {
    type Iter = vec::IntoIter<String>;
    fn read(&self, filename: &str) -> GkResult<Vec<u8>> {
        debug!("read: filename={filename}");
        self.session.read_file(filename).context("read file")?.ok_or(Error::NotFound)
    }
    fn write(&self, filename: &str, data: &[u8]) -> GkResult<()> {
        debug!("write: filename={filename}");
        self.session.write_file(filename, data, &OPEN_READ_WRITE).context("write to file")?;
        self.session.commit().context("commit write to file")
    }
    fn delete(&self, filename: &str) -> GkResult<()> {
        debug!("delete: filename={filename}");
        self.session.delete_file(filename).context("delete file")?;
        self.session.commit().context("commit delete file")
    }
    fn list(&self) -> GkResult<Self::Iter> {
        debug!("list files");
        self.session.list_files_in_dir("").map(|files| files.into_iter()).context("list files")
    }
}
