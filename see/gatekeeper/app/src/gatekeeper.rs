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

//! This module implements the IGatekeeper service with Trusted HAL

use alloc::rc::Rc;
use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
    GatekeeperEnrollResponse::GatekeeperEnrollResponse,
    GatekeeperVerifyResponse::GatekeeperVerifyResponse,
    IGatekeeper::{
        BnGatekeeper, IGatekeeper, ERROR_GENERAL_FAILURE, ERROR_NOT_IMPLEMENTED,
        ERROR_RETRY_TIMEOUT,
    },
};
use android_hardware_gatekeeper::binder;
use core::cell::RefCell;
use fragile::Fragile;
use gk_ta::{
    traits::{self, HmacKey, OpaqueOr},
    Error, GatekeeperTa,
};
use log::info;
use rpcbinder::RpcServer;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};

const IGATEKEEPER_PORT: &str = "android.hardware.gatekeeper.IGatekeeper/default";

pub struct NoOpHmacSha256;

impl traits::HmacSha256 for NoOpHmacSha256 {
    fn sign(&self, _key: &OpaqueOr<HmacKey>, _data: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!("NoOpHmacSha256::sign is not implemented for Gatekeeper HAL")
    }
}

pub struct NoOpStdClock;

impl traits::MonotonicClock for NoOpStdClock {
    fn now(&self) -> gk_wire::MillisecondsSinceEpoch {
        unimplemented!("NoOpStdClock::now is not implemented for Gatekeeper HAL")
    }
}

pub struct NoOpConstEq;

impl traits::ConstTimeEq for NoOpConstEq {
    fn eq(&self, _left: &[u8], _right: &[u8]) -> bool {
        unimplemented!("NoOpConstEq::eq is not implemented for Gatekeeper HAL")
    }
}

pub struct NoOpNonsecurePasswordKey;

impl traits::PasswordKeyRetrieval for NoOpNonsecurePasswordKey {
    fn key(&self) -> Result<OpaqueOr<HmacKey>, Error> {
        unimplemented!("NoOpNonsecurePasswordKey::key is not implemented for Gatekeeper HAL")
    }
}

pub struct NoOpStdFilesystem;

impl traits::SecureFilesystem for NoOpStdFilesystem {
    type Iter = NoOpStdDirIterator;
    fn read(&self, _filename: &str) -> Result<Vec<u8>, Error> {
        unimplemented!("NoOpStdFilesystem::read is not implemented for Gatekeeper HAL")
    }
    fn write(&self, _filename: &str, _data: &[u8]) -> Result<(), Error> {
        unimplemented!("NoOpStdFilesystem::write is not implemented for Gatekeeper HAL")
    }
    fn delete(&self, _filename: &str) -> Result<(), Error> {
        unimplemented!("NoOpStdFilesystem::delete is not implemented for Gatekeeper HAL")
    }
    fn list(&self) -> Result<Self::Iter, Error> {
        unimplemented!("NoOpStdFilesystem::list is not implemented for Gatekeeper HAL")
    }
}

pub struct NoOpStdDirIterator {}

impl Iterator for NoOpStdDirIterator {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        unimplemented!("NoOpStdDirIterator::next is not implemented for Gatekeeper HAL")
    }
}

fn gk_ta_error_to_service_error(err: gk_ta::Error) -> binder::Status {
    match err {
        gk_ta::Error::RetryTimeout(_timeout) => binder::Status::from(ERROR_RETRY_TIMEOUT),
        gk_ta::Error::Unimplemented => binder::Status::from(ERROR_NOT_IMPLEMENTED),
        gk_ta::Error::NotFound
        | gk_ta::Error::AllocationFailed
        | gk_ta::Error::Internal
        | gk_ta::Error::VerifyFailed
        | gk_ta::Error::InvalidArgument => binder::Status::from(ERROR_GENERAL_FAILURE),
    }
}

/// Service implementing the IGatekeeper AIDL interface.
///
/// This struct holds the wrapper for the `GatekeeperTa`.
pub struct GateKeeperWithTHal {
    gk_ta: Fragile<RefCell<GatekeeperTa>>,
}

impl GateKeeperWithTHal {
    /// Creates a new `IGatekeeper` binder.
    pub fn new_binder(gk_ta: Fragile<RefCell<GatekeeperTa>>) -> binder::Strong<dyn IGatekeeper> {
        let gatekeeper_with_thal = Self { gk_ta };
        BnGatekeeper::new_binder(gatekeeper_with_thal, binder::BinderFeatures::default())
    }
}

impl binder::Interface for GateKeeperWithTHal {}

impl IGatekeeper for GateKeeperWithTHal {
    fn deleteAllUsers(&self) -> binder::Result<()> {
        let mut ta = self
            .gk_ta
            .get()
            .try_borrow_mut()
            .expect("Gatekeeper TA is already borrowed; re-entrant call detected!");

        Ok(ta.delete_all_users().map_err(gk_ta_error_to_service_error)?)
    }

    fn deleteUser(&self, _user_id: i32) -> binder::Result<()> {
        unimplemented!("GateKeeperWithThal::deleteUser is not implemented for Gatekeeper HAL")
    }

    fn enroll(
        &self,
        _user_id: i32,
        _current_handle: &[u8],
        _current_password: &[u8],
        _new_password: &[u8],
    ) -> binder::Result<GatekeeperEnrollResponse> {
        unimplemented!("GateKeeperWithThal::enroll is not implemented for Gatekeeper HAL")
    }

    fn verify(
        &self,
        _user_id: i32,
        _challenge: i64,
        _handle: &[u8],
        _password: &[u8],
    ) -> binder::Result<GatekeeperVerifyResponse> {
        unimplemented!("GateKeeperWithThal::verify is not implemented for Gatekeeper HAL")
    }
}

wrap_service!(IGatekeeperService(RpcServer: UnbufferedService));

service_dispatcher! {
    enum GateKeeperServices {
        IGatekeeperService,
    }
}

pub fn main_loop() -> Result<(), TipcError> {
    info!("Starting GateKeeper with Trusted HAL TA!");
    let implementation = traits::Implementation {
        rng: Box::new(gk_boringssl::Rng),
        clock: Box::new(NoOpStdClock),
        compare: Box::new(NoOpConstEq),
        hmac: Box::new(NoOpHmacSha256),
        password: Box::new(NoOpNonsecurePasswordKey),
        auth_key: Box::new(traits::ExplicitAuthKey::new(Box::new(NoOpHmacSha256))),
        failures: Box::new(NoOpStdFilesystem),
        shared_secret: None,
    };
    let ta = GatekeeperTa::new(implementation);
    let service = GateKeeperWithTHal::new_binder(Fragile::new(RefCell::new(ta)));
    let direct_rpc_server = RpcServer::new(service.as_binder());
    let direct = IGatekeeperService(direct_rpc_server);

    let cfg = PortCfg::new(IGATEKEEPER_PORT)
        .expect("failed to create port config")
        .allow_ta_connect()
        .allow_ns_connect();

    let mut dispatcher = GateKeeperServices::<1>::new().expect("dispatcher creation failed");
    dispatcher
        .add_service(Rc::new(direct), cfg)
        .expect("failed to add direct IGateKeeper to dispatcher");
    // Set max connection count to 2 in order to accommodate multiple connections.
    // gatekeeperd establishes a connection, the other can be used by other clients/tests
    Manager::<_, _, 1, 2>::new_with_dispatcher(dispatcher, [])
        .expect("Manager could not be created")
        .run_event_loop()
}
