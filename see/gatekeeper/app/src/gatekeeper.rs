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
    IGatekeeper::{BnGatekeeper, IGatekeeper},
};
use android_hardware_gatekeeper::binder;
use log::info;
use rpcbinder::RpcServer;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};

const IGATEKEEPER_PORT: &str = "android.hardware.gatekeeper.IGatekeeper/default";

/// Service implementing the IGatekeeper AIDL interface.
pub struct GateKeeperWithTHal;

impl GateKeeperWithTHal {
    /// Creates a new `IGatekeeper` binder.
    pub fn new_binder() -> binder::Strong<dyn IGatekeeper> {
        BnGatekeeper::new_binder(Self, binder::BinderFeatures::default())
    }
}

impl binder::Interface for GateKeeperWithTHal {}

impl IGatekeeper for GateKeeperWithTHal {
    fn deleteAllUsers(&self) -> binder::Result<()> {
        unimplemented!("")
    }

    fn deleteUser(&self, _user_id: i32) -> binder::Result<()> {
        unimplemented!("")
    }

    fn enroll(
        &self,
        _user_id: i32,
        _current_handle: &[u8],
        _current_password: &[u8],
        _new_password: &[u8],
    ) -> binder::Result<GatekeeperEnrollResponse> {
        unimplemented!("")
    }

    fn verify(
        &self,
        _user_id: i32,
        _challenge: i64,
        _handle: &[u8],
        _password: &[u8],
    ) -> binder::Result<GatekeeperVerifyResponse> {
        unimplemented!("")
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
    let service = GateKeeperWithTHal::new_binder();
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
    Manager::<_, _, 1, 1>::new_with_dispatcher(dispatcher, [])
        .expect("Manager could not be created")
        .run_event_loop()
}
