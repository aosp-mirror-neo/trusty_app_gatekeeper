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

//! Provides common utility functions for error handling and type conversion.

use core::fmt::{Debug, Display};
use gk_ta::Error;
use log::error;

/// A convenient type alias for `Result<T, gk_ta::Error>.
pub(crate) type GkResult<T> = Result<T, Error>;

/// A helper trait to add contextual information to an error, reducing boilerplate.
pub(crate) trait Context<T> {
    /// Prepends context to a `Result`'s error, converting the error type if necessary.
    ///
    /// The context is evaluated lazily.
    fn with_context<C, F>(self, context: F) -> GkResult<T>
    where
        C: Display,
        F: FnOnce() -> C;

    fn context<C>(self, context: C) -> GkResult<T>
    where
        C: Display,
        Self: Sized,
    {
        self.with_context(|| context)
    }
}

/// Generic implementation for any Result whose error type implements `Debug`.
impl<T, E> Context<T> for Result<T, E>
where
    E: Debug,
{
    fn with_context<C, F>(self, context: F) -> GkResult<T>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        self.map_err(|e| {
            error!("{}: {:?}", context(), e);
            Error::Internal
        })
    }
}
