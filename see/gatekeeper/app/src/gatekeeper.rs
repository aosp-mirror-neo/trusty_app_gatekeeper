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

use crate::{common::GkResult, filesystem::VmSecureFilesystem, hwcrypto_auth::HwCryptoAuthKey};
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
use core::cell::{RefCell, RefMut};
use fragile::Fragile;
use gk_ta::{
    traits::{self, HmacKey, OpaqueOr},
    Error, GatekeeperTa,
};
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

    /// Borrows the TA and throws error on re-entrant calls.
    fn ta(&self) -> binder::Result<RefMut<'_, GatekeeperTa>> {
        self.gk_ta.get().try_borrow_mut().map_err(|_| {
            binder::Status::new_service_specific_error_str(
                ERROR_GENERAL_FAILURE,
                Some("Gatekeeper TA is busy (re-entrant call detected)"),
            )
        })
    }
}

impl binder::Interface for GateKeeperWithTHal {}

impl IGatekeeper for GateKeeperWithTHal {
    fn deleteAllUsers(&self) -> binder::Result<()> {
        let mut ta = self.ta()?;
        Ok(ta.delete_all_users().map_err(gk_ta_error_to_service_error)?)
    }

    fn deleteUser(&self, user_id: i32) -> binder::Result<()> {
        let mut ta = self.ta()?;
        let user_id = gk_wire::AndroidUserId(user_id);
        Ok(ta.delete_user(user_id).map_err(gk_ta_error_to_service_error)?)
    }

    fn enroll(
        &self,
        user_id: i32,
        current_handle: &[u8],
        current_password: &[u8],
        new_password: &[u8],
    ) -> binder::Result<GatekeeperEnrollResponse> {
        let mut ta = self.ta()?;
        let user_id = gk_wire::AndroidUserId(user_id);
        let current_handle = gk_wire::PasswordHandle::from_raw(current_handle);
        let current_password = gk_wire::Password::from_raw(current_password);
        let new_password = gk_wire::Password(new_password.to_vec());
        let response = ta.enroll(user_id, &current_handle, &current_password, &new_password);
        match response {
            Ok((sid, handle)) => Ok(GatekeeperEnrollResponse {
                statusCode: STATUS_OK,
                timeoutMs: 0,
                secureUserId: sid.0,
                data: handle.0,
            }),
            Err(gk_ta::Error::RetryTimeout(timeout)) => Ok(GatekeeperEnrollResponse {
                statusCode: ERROR_RETRY_TIMEOUT,
                timeoutMs: timeout,
                secureUserId: 0,
                data: Vec::new(),
            }),
            Err(e) => Err(gk_ta_error_to_service_error(e)),
        }
    }

    fn verify(
        &self,
        user_id: i32,
        challenge: i64,
        handle: &[u8],
        password: &[u8],
    ) -> binder::Result<GatekeeperVerifyResponse> {
        let mut ta = self.ta()?;
        let user_id = gk_wire::AndroidUserId(user_id);
        let handle = gk_wire::PasswordHandle(handle.to_vec());
        let password = gk_wire::Password(password.to_vec());
        let response = ta.verify(user_id, challenge, &handle, &password);
        match response {
            Ok((request_reenroll, auth_token)) => Ok(GatekeeperVerifyResponse {
                statusCode: if request_reenroll { STATUS_REENROLL } else { STATUS_OK },
                timeoutMs: 0,
                hardwareAuthToken: token_to_aidl(auth_token),
            }),
            Err(gk_ta::Error::RetryTimeout(timeout)) => Ok(GatekeeperVerifyResponse {
                statusCode: ERROR_RETRY_TIMEOUT,
                timeoutMs: timeout,
                hardwareAuthToken: empty_auth_token(),
            }),
            Err(e) => Err(gk_ta_error_to_service_error(e)),
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

fn new_gatekeeper_ta() -> GkResult<GatekeeperTa> {
    let implementation = traits::Implementation {
        rng: Box::new(gk_boringssl::Rng),
        clock: Box::new(TrustyMonotonicClock),
        compare: Box::new(gk_boringssl::ConstEq),
        hmac: Box::new(gk_boringssl::HmacSha256),
        password: Box::new(NoOpNonsecurePasswordKey),
        auth_key: Box::new(HwCryptoAuthKey::new()?),
        failures: Box::new(VmSecureFilesystem::new()?),
        shared_secret: None,
    };
    Ok(GatekeeperTa::new(implementation))
}

pub fn main_loop() -> Result<(), TipcError> {
    info!("Starting GateKeeper with Trusted HAL TA!");
    let ta = new_gatekeeper_ta().expect("initialize GatekeeperTa");
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
