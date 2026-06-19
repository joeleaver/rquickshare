// Advertises this device as a discoverable Quick Share RECEIVER over BLE so the
// new (unified) Quick Share on Android can find it.
//
// rquickshare advertises receivers over mDNS (WiFi LAN), but current Quick Share
// does not browse mDNS for receivers — it discovers them via a BLE advertisement
// and only then connects over the negotiated medium. Without this advert, modern
// Android phones never list a Linux receiver. (See NearDrop/rquickshare issues.)
//
// We emit a real Nearby Connections `BleAdvertisement` (service UUID 0xFEF3,
// connectable + LE extended) carrying THIS receiver's endpoint_id, so the phone
// correlates it with our mDNS/WiFi-LAN endpoint and connects to the TCP receiver.
//
// v1 advertises a WiFi-LAN-only receiver: we deliberately omit the Bluetooth
// mediums (zeroed BLUETOOTH_MAC, no L2CAP capability tail) so the phone connects
// over WiFi to the existing TCP server instead of a BLE L2CAP channel (which
// would require a Nearby Connections CoC server — future work for BT-only nets).
//
// Advertisement layout (google/nearby connections/.../ble_advertisement.*):
//   8B prefix:  0x48 fc9f5e 000000 [bt_mac_offset]
//   advert:     [ver+pcp=0x23][svc_hash fc9f5e][endpoint_id 4][ep_info_size]
//               [ep_info][BLUETOOTH_MAC=0 (6)][uwb_size=0][extra=0]
//   ep_info:    [0x20|device_type<<1][salt 16][name_len][name]
//
// NOTE: Linux/BlueZ only — macOS cannot emit these adverts.

use std::collections::{BTreeMap, BTreeSet};

use bluer::adv::{Advertisement, SecondaryChannel, Type};
use bluer::gatt::local::{Application, Characteristic, CharacteristicRead, Service};
use bluer::UuidExt;
use futures::FutureExt;
use rand::Rng;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{advertisement_uuid, build_advertisement_header};

const INNER_NAME: &str = "BleConnectionsAdvertiser";

// First 3 bytes of SHA-256("NearbySharing"): the Quick Share service id.
const SERVICE_ID_HASH: [u8; 3] = [0xfc, 0x9f, 0x5e];
// Nearby Presence service UUID used by Quick Share discovery adverts.
const NEARBY_PRESENCE_UUID: u16 = 0xFEF3;
// Nearby Connections device type for "laptop"/computer.
const DEVICE_TYPE_LAPTOP: u8 = 3;

pub struct BleConnectionsAdvertiser {
    adapter: bluer::Adapter,
    endpoint_id: [u8; 4],
    device_name: String,
    // L2CAP PSM to advertise so a sender will attempt a BLE L2CAP connection.
    // 0 = don't offer L2CAP (WiFi-LAN-only, the original behaviour).
    psm: u16,
    // The inner BleAdvertisement, built ONCE (random salt) and shared so the
    // header's advertisement_hash matches what we serve over L2CAP/GATT.
    inner: Vec<u8>,
}

impl BleConnectionsAdvertiser {
    pub async fn new(
        endpoint_id: [u8; 4],
        device_name: String,
        psm: u16,
        inner: Vec<u8>,
    ) -> Result<Self, anyhow::Error> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;
        Ok(Self {
            adapter,
            endpoint_id,
            device_name,
            psm,
            inner,
        })
    }
}

/// Build the inner Nearby Connections `BleAdvertisement` (endpoint info + PSM
/// extra-field). Built once and shared between the advert header (its hash) and
/// the L2CAP `RESPONSE_ADVERTISEMENT`, so the hash the phone requests matches.
pub fn build_inner_advertisement(endpoint_id: [u8; 4], device_name: &str, psm: u16) -> Vec<u8> {
    {
        let name = device_name.as_bytes();

        // endpoint_info = Quick Share advertisement (Everyone mode -> plaintext name)
        let salt: [u8; 16] = rand::rng().random();
        let mut ei = Vec::with_capacity(18 + name.len());
        ei.push(0x20 | (DEVICE_TYPE_LAPTOP << 1));
        ei.extend_from_slice(&salt);
        ei.push(name.len() as u8);
        ei.extend_from_slice(name);

        // bt_mac_offset = prefix(8) + ver+pcp(1) + svc_hash(3) + endpoint_id(4)
        //                 + ep_info_size(1) + ep_info  =  17 + ei.len()
        let bt_mac_offset = (17 + ei.len()) as u8;

        let mut p = Vec::new();
        // 8-byte prefix
        p.push(0x48);
        p.extend_from_slice(&SERVICE_ID_HASH);
        p.extend_from_slice(&[0, 0, 0]);
        p.push(bt_mac_offset);
        // Nearby Connections BleAdvertisement
        p.push(0x23); // version(1)<<5 | pcp(P2P_POINT_TO_POINT=3)
        p.extend_from_slice(&SERVICE_ID_HASH);
        p.extend_from_slice(&endpoint_id);
        p.push(ei.len() as u8);
        p.extend_from_slice(&ei);
        p.extend_from_slice(&[0u8; 6]); // BLUETOOTH_MAC zeroed -> no BT classic
        p.push(0); // uwb_size
        // extra_fields bitmask + trailing optional fields. kPsmBitmask = 0x01,
        // followed by the 2-byte big-endian L2CAP PSM, tells the sender it can
        // connect over a BLE L2CAP CoC. 0 = no extra fields (WiFi-LAN-only).
        if psm != 0 {
            p.push(0x01); // extra_fields: PSM present
            p.extend_from_slice(&psm.to_be_bytes());
        } else {
            p.push(0); // no extra fields
        }
        p
    }
}

impl BleConnectionsAdvertiser {
    pub async fn run(self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        // Mode 3: broadcast a 17-byte header; the sender fetches the full inner
        // BleAdvertisement over L2CAP (REQUEST_ADVERTISEMENT), then opens the
        // data connection.
        let inner = self.inner.clone();
        let header = build_advertisement_header(self.psm, &inner);
        let char_uuid = advertisement_uuid(0);

        info!(
            "{INNER_NAME}: advertising '{}' (header {}B, inner {}B), endpoint_id={:?}, l2cap_psm={:#06x}, char={char_uuid}",
            self.device_name,
            header.len(),
            inner.len(),
            self.endpoint_id,
            self.psm
        );

        // GATT server: serve the inner advertisement at slot 0 (read-only).
        let app = Application {
            services: vec![Service {
                uuid: Uuid::from_u16(NEARBY_PRESENCE_UUID),
                primary: true,
                characteristics: vec![Characteristic {
                    uuid: char_uuid,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |req| {
                            let inner = inner.clone();
                            async move {
                                let off = req.offset as usize;
                                Ok(inner.get(off..).map(|s| s.to_vec()).unwrap_or_default())
                            }
                            .boxed()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let gatt_handle = self.adapter.serve_gatt_application(app).await?;
        info!("{INNER_NAME}: GATT server registered (service {NEARBY_PRESENCE_UUID:#06x})");

        // Broadcast the header under the 0xFEF3 service data.
        let mut service_data: BTreeMap<Uuid, Vec<u8>> = BTreeMap::new();
        service_data.insert(Uuid::from_u16(NEARBY_PRESENCE_UUID), header);
        let mut service_uuids: BTreeSet<Uuid> = BTreeSet::new();
        service_uuids.insert(Uuid::from_u16(NEARBY_PRESENCE_UUID));

        let adv = Advertisement {
            advertisement_type: Type::Peripheral, // connectable
            discoverable: Some(true),
            service_uuids,
            service_data,
            secondary_channel: Some(SecondaryChannel::OneM), // LE extended advertising
            ..Default::default()
        };

        let adv_handle = self.adapter.advertise(adv).await?;
        info!("{INNER_NAME}: advertisement registered");
        ctk.cancelled().await;
        info!("{INNER_NAME}: cancelled, stopping");
        drop(adv_handle);
        drop(gatt_handle);
        Ok(())
    }
}
