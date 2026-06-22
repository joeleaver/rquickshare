use std::collections::HashMap;
use std::sync::Arc;

use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use self::info::{InternalFileInfo, TransferMetadata};
use crate::securegcm::ukey2_client_init::CipherCommitment;
use crate::utils::RemoteDeviceInfo;

#[cfg(feature = "experimental")]
mod ble;
#[cfg(feature = "experimental")]
pub use ble::*;
#[cfg(all(feature = "experimental", target_os = "linux"))]
mod blea;
#[cfg(all(feature = "experimental", target_os = "linux"))]
pub use blea::*;
#[cfg(all(feature = "experimental", target_os = "linux"))]
mod blea2;
#[cfg(all(feature = "experimental", target_os = "linux"))]
pub use blea2::*;
#[cfg(all(feature = "experimental", target_os = "linux"))]
mod ble_header;
#[cfg(all(feature = "experimental", target_os = "linux"))]
pub use ble_header::*;
#[cfg(all(feature = "experimental", target_os = "linux"))]
mod ble_discovery;
#[cfg(all(feature = "experimental", target_os = "linux"))]
pub use ble_discovery::*;
#[cfg(all(feature = "experimental", target_os = "linux"))]
mod l2cap;
#[cfg(all(feature = "experimental", target_os = "linux"))]
pub use l2cap::*;
mod inbound;
pub use inbound::*;
pub(crate) mod info;
mod ukey_session;
pub use ukey_session::UkeySession;
// Staged for the QS_BWU_ACTOR receive-path inversion; re-exported when wired in.
mod bwu_channel;
// Linux SoftAP for the WIFI_HOTSPOT bandwidth upgrade (Phase 4). Off by default.
// Internal to the crate: l2cap.rs constructs NmSoftAp directly (no re-export).
#[cfg(all(feature = "linux-softap", target_os = "linux"))]
mod nm_softap;
mod mdns_discovery;
pub use mdns_discovery::*;
mod mdns;
pub use mdns::*;
mod outbound;
pub use outbound::*;

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS, PartialEq)]
#[ts(export)]
pub enum State {
    #[default]
    Initial,
    ReceivedConnectionRequest,
    SentUkeyServerInit,
    SentUkeyClientInit,
    SentUkeyClientFinish,
    SentPairedKeyEncryption,
    ReceivedUkeyClientFinish,
    SentConnectionResponse,
    SentPairedKeyResult,
    SentIntroduction,
    ReceivedPairedKeyResult,
    WaitingForUserConsent,
    ReceivingFiles,
    SendingFiles,
    Disconnected,
    Rejected,
    Cancelled,
    Finished,
}

#[derive(Debug, Default)]
pub struct InnerState {
    pub id: String,
    pub server_seq: i32,
    pub client_seq: i32,
    pub encryption_done: bool,

    // Subject to be used-facing for progress, ...
    pub state: State,
    pub remote_device_info: Option<RemoteDeviceInfo>,
    pub pin_code: Option<String>,
    pub transfer_metadata: Option<TransferMetadata>,
    pub transferred_files: HashMap<i64, InternalFileInfo>,

    // Everything needed for encryption/decryption/verif
    pub cipher_commitment: Option<CipherCommitment>,
    pub private_key: Option<SecretKey>,
    pub public_key: Option<PublicKey>,
    pub server_init_data: Option<Vec<u8>>,
    pub client_init_msg_data: Option<Vec<u8>>,
    pub ukey_client_finish_msg_data: Option<Vec<u8>>,
    pub decrypt_key: Option<Vec<u8>>,
    pub recv_hmac_key: Option<Vec<u8>>,
    pub encrypt_key: Option<Vec<u8>>,
    pub send_hmac_key: Option<Vec<u8>>,
    // The shared d2d cipher built from the four keys above. Authoritative for the
    // sequence counters; the same Arc survives the L2CAP->WiFi swap so the
    // sequence stays continuous, and it satisfies nearby_rs::bwu::Cipher for the
    // bandwidth-upgrade port. None until UKEY2 key derivation completes.
    pub session: Option<Arc<UkeySession>>,

    // Used to handle/track ingress transfer
    pub text_payload: Option<TextPayloadInfo>,
    // pub text_payload_id: i64,
    // pub text_is_url: bool,
    // pub wifi_ssid: Option<String>,
    pub payload_buffers: HashMap<i64, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum TextPayloadInfo {
    Url(i64),
    Text(i64),
    Wifi((i64, String)),
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub enum TextPayloadType {
    Url,
    Text,
    Wifi,
}

impl TextPayloadInfo {
    fn get_i64_value(&self) -> i64 {
        match self {
            TextPayloadInfo::Url(value)
            | TextPayloadInfo::Text(value)
            | TextPayloadInfo::Wifi((value, _)) => value.to_owned(),
        }
    }
}
