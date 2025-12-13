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

use crate::hwcrypto_auth::HwCryptoAuthKey;
use alloc::rc::Rc;
use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
    GatekeeperEnrollResponse::GatekeeperEnrollResponse,
    GatekeeperVerifyResponse::GatekeeperVerifyResponse,
    IGatekeeper::{
        BnGatekeeper, IGatekeeper, ERROR_GENERAL_FAILURE, ERROR_NOT_IMPLEMENTED,
        ERROR_RETRY_TIMEOUT, STATUS_OK, STATUS_REENROLL,
    },
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use android_hardware_gatekeeper::binder;
use core::cell::RefCell;
use fragile::Fragile;
use gk_ta::{
    traits::{self, HmacKey, OpaqueOr},
    Error, GatekeeperTa,
};
use gk_wire::{PerformOpResponse, PerformOpReq, PerformOpRsp};
use hal_wire::AsCborValue;
use log::info;
use rpcbinder::RpcServer;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};

const IGATEKEEPER_PORT: &str = "android.hardware.gatekeeper.IGatekeeper/default";

struct TrustyMonotonicClock;

impl traits::MonotonicClock for TrustyMonotonicClock {
    fn now(&self) -> gk_wire::MillisecondsSinceEpoch {
        gk_wire::MillisecondsSinceEpoch(trusty_clock::now().into())
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

    fn execute_req(&self, req: PerformOpReq) -> binder::Result<PerformOpResponse> {
        let mut ta = self
            .gk_ta
            .get()
            .try_borrow_mut()
            .expect("Gatekeeper TA is already borrowed; re-entrant call detected!");

        let req_data = req.into_vec().map_err(|_| {
            binder::Status::new_exception(binder::ExceptionCode::BAD_PARCELABLE, None)
        })?;

        let rsp_data = ta.process(&req_data);
        PerformOpResponse::from_slice(&rsp_data)
            .map_err(|_| binder::Status::new_exception(binder::ExceptionCode::BAD_PARCELABLE, None))
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

    fn deleteUser(&self, user_id: i32) -> binder::Result<()> {
        let user_id = gk_wire::AndroidUserId(user_id);
        let req = PerformOpReq::DeleteUser(gk_wire::DeleteUserRequest { user_id });
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::DeleteUser(_)) => Ok(()),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(_) => Err(binder::Status::new_service_specific_error(
                gk_wire::ApiStatus::RetryTimeout as i32,
                None,
            )),
            PerformOpResponse::Err(rc) => Err(binder::Status::new_service_specific_error(rc, None)),
        }
    }

    fn enroll(
        &self,
        user_id: i32,
        current_handle: &[u8],
        current_password: &[u8],
        new_password: &[u8],
    ) -> binder::Result<GatekeeperEnrollResponse> {
        let user_id = gk_wire::AndroidUserId(user_id);
        let current_handle = gk_wire::PasswordHandle::from_raw(current_handle);
        let current_password = gk_wire::Password::from_raw(current_password);
        let new_password = gk_wire::Password(new_password.to_vec());
        let req = PerformOpReq::Enroll(gk_wire::EnrollRequest {
            user_id,
            current_handle,
            current_password,
            new_password,
        });
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::Enroll(rsp)) => Ok(GatekeeperEnrollResponse {
                statusCode: STATUS_OK,
                timeoutMs: 0,
                secureUserId: rsp.sid.0,
                data: rsp.handle.0,
            }),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => Ok(GatekeeperEnrollResponse {
                statusCode: ERROR_RETRY_TIMEOUT,
                timeoutMs: timeout,
                secureUserId: 0,
                data: Vec::new(),
            }),
            PerformOpResponse::Err(rc) => Err(binder::Status::new_service_specific_error(rc, None)),
        }
    }

    fn verify(
        &self,
        user_id: i32,
        challenge: i64,
        handle: &[u8],
        password: &[u8],
    ) -> binder::Result<GatekeeperVerifyResponse> {
        let user_id = gk_wire::AndroidUserId(user_id);
        let handle = gk_wire::PasswordHandle(handle.to_vec());
        let password = gk_wire::Password(password.to_vec());
        let req =
            PerformOpReq::Verify(gk_wire::VerifyRequest { user_id, challenge, handle, password });
        match self.execute_req(req)? {
            PerformOpResponse::Ok(PerformOpRsp::Verify(rsp)) => Ok(GatekeeperVerifyResponse {
                statusCode: if rsp.request_reenroll { STATUS_REENROLL } else { STATUS_OK },
                timeoutMs: 0,
                hardwareAuthToken: token_to_aidl(rsp.auth_token),
            }),
            PerformOpResponse::Ok(_) => {
                Err(binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_STATE, None))
            }
            PerformOpResponse::RetryTimeout(timeout) => Ok(GatekeeperVerifyResponse {
                statusCode: ERROR_RETRY_TIMEOUT,
                timeoutMs: timeout,
                hardwareAuthToken: empty_auth_token(),
            }),
            PerformOpResponse::Err(rc) => Err(binder::Status::new_service_specific_error(rc, None)),
        }
    }
}

fn token_to_aidl(token: gk_wire::HardwareAuthToken) -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: token.challenge,
        userId: token.user_id,
        authenticatorId: token.authenticator_id,
        authenticatorType: auth_type_to_aidl(token.authenticator_type),
        timestamp: Timestamp { milliSeconds: token.timestamp.0 },
        mac: token.mac,
    }
}

/// Convert a [`gk_wire::HardwareAuthenticatorType`] into an AIDL [`HardwareAuthenticatorType`].
fn auth_type_to_aidl(auth_type: gk_wire::HardwareAuthenticatorType) -> HardwareAuthenticatorType {
    match auth_type {
        gk_wire::HardwareAuthenticatorType::None => HardwareAuthenticatorType::NONE,
        gk_wire::HardwareAuthenticatorType::Password => HardwareAuthenticatorType::PASSWORD,
        gk_wire::HardwareAuthenticatorType::Fingerprint => HardwareAuthenticatorType::FINGERPRINT,
        gk_wire::HardwareAuthenticatorType::Any => HardwareAuthenticatorType::ANY,
    }
}

fn empty_auth_token() -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: 0,
        userId: 0,
        authenticatorId: 0,
        authenticatorType: HardwareAuthenticatorType::NONE,
        timestamp: Timestamp { milliSeconds: 0 },
        mac: Vec::new(),
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
        clock: Box::new(TrustyMonotonicClock),
        compare: Box::new(gk_boringssl::ConstEq),
        hmac: Box::new(gk_boringssl::HmacSha256),
        password: Box::new(NoOpNonsecurePasswordKey),
        auth_key: Box::new(HwCryptoAuthKey::new().expect("HwCryptoAuthKey initialization failed")),
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
