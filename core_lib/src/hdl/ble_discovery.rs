// PC->phone send discovery over BLE. This is the inverse of `blea2.rs`: where
// the receiver side *builds* the 0xFEF3 advertisement header + inner Nearby
// Connections `BleAdvertisement`, here we *parse* them to discover a phone that
// is "visible to everyone" (a Quick Share receiver) and recover the bits needed
// to connect: its endpoint_id, device name, and L2CAP PSM.
//
// Format is documented in `ble_header.rs` (header) and `blea2.rs`
// (`build_inner_advertisement`) and matches google/nearby. The parsers below are
// validated by round-tripping against those builders (see tests) — no packet
// captures required.

use std::collections::{HashMap, HashSet};

use anyhow::anyhow;
use bluer::{Adapter, AdapterEvent, Address, Device, DiscoveryFilter, DiscoveryTransport, UuidExt};
use futures::{pin_mut, StreamExt};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{advertisement_uuid, EndpointInfo};
use crate::DeviceType;

const NEARBY_PRESENCE_UUID: u16 = 0xFEF3;
const INNER_NAME: &str = "BleDiscovery";

/// Parsed 0xFEF3 advertisement header (see `build_advertisement_header`):
/// `[ver<<5|ext<<4|slots][bloom(10)][hash(4)][psm(2)]`.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvertisementHeader {
    pub version: u8,
    pub num_slots: u8,
    pub advertisement_hash: [u8; 4],
    /// L2CAP PSM, or 0 / None when the header carries no PSM tail.
    pub psm: Option<u16>,
}

/// Parse the 0xFEF3 service-data header. Tolerates trailing bytes (some senders
/// append extra fields). Returns None if it is too short to be a V2 header.
pub fn parse_advertisement_header(b: &[u8]) -> Option<AdvertisementHeader> {
    // 1 (ver/slots) + 10 (bloom) + 4 (hash) = 15 minimum; +2 for the PSM tail.
    const MIN: usize = 1 + 10 + 4;
    if b.len() < MIN {
        return None;
    }
    let version = (b[0] >> 5) & 0x07;
    let num_slots = b[0] & 0x0F;
    let advertisement_hash: [u8; 4] = b[11..15].try_into().ok()?;
    let psm = if b.len() >= MIN + 2 {
        Some(u16::from_be_bytes([b[15], b[16]]))
    } else {
        None
    };
    Some(AdvertisementHeader {
        version,
        num_slots,
        advertisement_hash,
        psm,
    })
}

/// A phone discovered as a Quick Share receiver.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredEndpoint {
    pub endpoint_id: [u8; 4],
    pub device_name: String,
    pub device_type: u8,
    /// L2CAP PSM advertised in the inner advertisement's extra fields (0 = none).
    pub psm: u16,
}

/// Parse the inner Nearby Connections `BleAdvertisement` (served over GATT, or
/// inlined). Inverse of `blea2::build_inner_advertisement`:
///   8B prefix: 0x48 svc_hash(3) 00 00 00 bt_mac_offset
///   [ver+pcp=0x23][svc_hash(3)][endpoint_id(4)][ep_info_size][ep_info]
///   [BLUETOOTH_MAC(6)][uwb_size][extra_fields(+psm)]
///   ep_info: [0x20|device_type<<1][salt(16)][name_len][name]
pub fn parse_inner_advertisement(p: &[u8]) -> Option<DiscoveredEndpoint> {
    // Skip the 8-byte prefix (marker + service-id hash + bt_mac_offset).
    let mut i = 8usize;
    let ver_pcp = *p.get(i)?;
    i += 1;
    // version is the top 3 bits; Quick Share uses v1.
    if (ver_pcp >> 5) & 0x07 == 0 {
        return None;
    }
    i += 3; // service_id_hash
    let endpoint_id: [u8; 4] = p.get(i..i + 4)?.try_into().ok()?;
    i += 4;
    let ep_info_size = *p.get(i)? as usize;
    i += 1;
    let ei = p.get(i..i + ep_info_size)?;
    i += ep_info_size;
    let (device_name, device_type) = parse_endpoint_info(ei)?;

    i += 6; // BLUETOOTH_MAC
    let uwb_size = *p.get(i)? as usize;
    i += 1 + uwb_size;

    // extra_fields: a bitmask byte; bit0 (0x01) => 2-byte big-endian L2CAP PSM.
    let mut psm = 0u16;
    if let Some(&extra) = p.get(i) {
        i += 1;
        if extra & 0x01 != 0 {
            if let Some(b) = p.get(i..i + 2) {
                psm = u16::from_be_bytes([b[0], b[1]]);
            }
        }
    }

    Some(DiscoveredEndpoint {
        endpoint_id,
        device_name,
        device_type,
        psm,
    })
}

/// Parse the Quick Share endpoint_info: `[0x20|type<<1][salt(16)][len][name]`.
fn parse_endpoint_info(ei: &[u8]) -> Option<(String, u8)> {
    // 1 (flags/type) + 16 (salt) + 1 (name_len) = 18 minimum.
    if ei.len() < 18 {
        return None;
    }
    let device_type = (ei[0] >> 1) & 0x07;
    let name_len = ei[17] as usize;
    let name = ei.get(18..18 + name_len)?;
    Some((String::from_utf8_lossy(name).to_string(), device_type))
}

/// Stable discovery id for a BLE endpoint (the Bluetooth address is stable; the
/// Nearby endpoint_id and advert hash rotate). beamish keys its device list on
/// this and uses the `ble:` prefix to route a send over L2CAP instead of TCP.
#[inline]
fn ble_id(addr: Address) -> String {
    format!("ble:{addr}")
}

/// Scans for "visible to everyone" Quick Share receivers (Nearby Presence
/// service 0xFEF3) and emits them into `discovery()`'s `EndpointInfo` stream.
///
/// This is the runtime counterpart to the parsers above: scan 0xFEF3 → parse the
/// advertisement header (PSM + dedup hash) → GATT-read the inner BleAdvertisement
/// → `parse_inner_advertisement` (endpoint name + type + L2CAP PSM) → emit an
/// `EndpointInfo` that carries the Bluetooth address + PSM but no ip/port.
pub struct BleDiscovery {
    adapter: Adapter,
    sender: broadcast::Sender<EndpointInfo>,
}

impl BleDiscovery {
    pub async fn new(sender: broadcast::Sender<EndpointInfo>) -> Result<Self, anyhow::Error> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;
        Ok(Self { adapter, sender })
    }

    pub async fn run(self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        let svc = Uuid::from_u16(NEARBY_PRESENCE_UUID);

        // Surface only devices advertising Nearby Presence, and keep advert
        // refreshes coming (`duplicate_data`) so service data that lands after
        // the first DeviceAdded is delivered as further DeviceAdded re-fires.
        let filter = DiscoveryFilter {
            uuids: [svc].into_iter().collect(),
            transport: DiscoveryTransport::Le,
            duplicate_data: true,
            ..Default::default()
        };
        if let Err(e) = self.adapter.set_discovery_filter(filter).await {
            warn!("{INNER_NAME}: couldn't set discovery filter ({e}); scanning unfiltered");
        }

        info!("{INNER_NAME}: scanning for Quick Share receivers (service {svc})");
        let events = self.adapter.discover_devices_with_changes().await?;
        pin_mut!(events);

        // addr -> advert hash we last emitted, so the flood of property-change
        // re-fires doesn't reconnect + re-GATT-read the same advertisement.
        let mut emitted: HashMap<Address, [u8; 4]> = HashMap::new();
        // Addresses fully resolved over GATT: never reconnect to them again (a
        // reconnect storm during a Wi-Fi transfer starves the 2.4GHz radio and
        // stalls it). They stay listed until the device leaves.
        let mut resolved: HashSet<Address> = HashSet::new();

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: cancelled, stopping scan");
                    break;
                }
                ev = events.next() => {
                    match ev {
                        Some(AdapterEvent::DeviceAdded(addr)) => {
                            if let Err(e) = self.on_device(addr, &mut emitted, &mut resolved).await {
                                debug!("{INNER_NAME}: {addr}: {e}");
                            }
                        }
                        Some(AdapterEvent::DeviceRemoved(addr)) => {
                            resolved.remove(&addr);
                            if emitted.remove(&addr).is_some() {
                                info!("{INNER_NAME}: {addr} left");
                                let _ = self.sender.send(EndpointInfo {
                                    id: ble_id(addr),
                                    present: Some(false),
                                    ..Default::default()
                                });
                            }
                        }
                        Some(_) => {}
                        None => {
                            info!("{INNER_NAME}: device stream ended");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn on_device(
        &self,
        addr: Address,
        emitted: &mut HashMap<Address, [u8; 4]>,
        resolved: &mut HashSet<Address>,
    ) -> Result<(), anyhow::Error> {
        // Already fully resolved over GATT — it's listed; don't reconnect.
        if resolved.contains(&addr) {
            return Ok(());
        }

        let device = self.adapter.device(addr)?;
        let svc = Uuid::from_u16(NEARBY_PRESENCE_UUID);

        // The 0xFEF3 service data is the advertisement HEADER (bloom + hash + PSM).
        let header_bytes = match device.service_data().await? {
            Some(sd) => match sd.get(&svc) {
                Some(b) => b.clone(),
                None => return Ok(()),
            },
            None => return Ok(()),
        };
        let header = match parse_advertisement_header(&header_bytes) {
            Some(h) => h,
            None => return Ok(()),
        };

        // Already processed this exact advert? Skip the GATT round-trip.
        if emitted.get(&addr) == Some(&header.advertisement_hash) {
            return Ok(());
        }

        // Recover the inner advert (endpoint name + type + PSM) over GATT. If the
        // receiver serves it over L2CAP instead (some do), fall back to the
        // device's Bluetooth alias so it still appears with a usable label.
        let endpoint = match self.read_inner(&device, header.num_slots).await {
            Ok(bytes) => parse_inner_advertisement(&bytes),
            Err(e) => {
                debug!("{INNER_NAME}: {addr}: GATT inner-advert read failed ({e})");
                None
            }
        };

        let (name, rtype, inner_psm) = match &endpoint {
            Some(d) => (
                d.device_name.clone(),
                Some(DeviceType::from_raw_value(d.device_type)),
                d.psm,
            ),
            None => (
                device.alias().await.unwrap_or_default(),
                Some(DeviceType::Phone),
                0,
            ),
        };
        // Prefer the inner-advert PSM; fall back to the header's.
        let psm = if inner_psm != 0 { inner_psm } else { header.psm.unwrap_or(0) };
        let name = if name.trim().is_empty() {
            format!("Nearby device ({addr})")
        } else {
            name
        };

        let ei = EndpointInfo {
            fullname: ble_id(addr),
            id: ble_id(addr),
            name: Some(name),
            ip: None,
            port: None,
            rtype,
            present: Some(true),
            bt_address: Some(addr.to_string()),
            psm: if psm != 0 { Some(psm) } else { None },
        };
        info!("{INNER_NAME}: discovered receiver {ei:?}");
        let _ = self.sender.send(ei);
        emitted.insert(addr, header.advertisement_hash);
        // A clean GATT read means we have everything we'll ever need from this
        // device; stop reconnecting to it. A fallback (alias) stays retryable so
        // a later advert can still upgrade it to the real name.
        if endpoint.is_some() {
            resolved.insert(addr);
        }
        Ok(())
    }

    /// GATT-read the inner BleAdvertisement from the 0xFEF3 service. Connects if
    /// needed, and disconnects afterward only if we opened the connection.
    async fn read_inner(&self, device: &Device, num_slots: u8) -> Result<Vec<u8>, anyhow::Error> {
        let we_connected = if !device.is_connected().await? {
            timeout(Duration::from_secs(10), device.connect())
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            true
        } else {
            false
        };

        // BlueZ resolves the GATT database a moment after connecting; reading
        // characteristics before that yields an empty service list.
        let resolved = timeout(Duration::from_secs(10), async {
            while !device.is_services_resolved().await.unwrap_or(false) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        if resolved.is_err() {
            debug!("{INNER_NAME}: services not resolved in time, reading anyway");
        }

        let result = self.read_inner_chars(device, num_slots).await;

        if we_connected {
            let _ = device.disconnect().await;
        }
        result
    }

    async fn read_inner_chars(
        &self,
        device: &Device,
        num_slots: u8,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let svc_uuid = Uuid::from_u16(NEARBY_PRESENCE_UUID);
        let services = timeout(Duration::from_secs(10), device.services())
            .await
            .map_err(|_| anyhow!("service discovery timed out"))??;

        for svc in services {
            if svc.uuid().await? != svc_uuid {
                continue;
            }
            // The advert lives in the characteristic whose UUID is the slot base
            // OR'd with the slot index; try each advertised slot, else the first
            // characteristic in the service.
            let chars = svc.characteristics().await?;
            let wanted: Vec<Uuid> = (0..=num_slots.max(1)).map(advertisement_uuid).collect();
            for ch in &chars {
                if wanted.contains(&ch.uuid().await?) {
                    return Ok(ch.read().await?);
                }
            }
            if let Some(ch) = chars.first() {
                return Ok(ch.read().await?);
            }
        }
        Err(anyhow!("0xFEF3 advertisement characteristic not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hdl::{build_advertisement_header, build_inner_advertisement};

    #[test]
    fn header_roundtrip() {
        let inner = b"some inner advertisement bytes";
        let header = build_advertisement_header(0x0083, inner);
        let parsed = parse_advertisement_header(&header).expect("header parses");
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.num_slots, 1);
        assert_eq!(parsed.psm, Some(0x0083));
        // The hash must match SHA256(inner)[:4] that the builder embedded.
        use sha2::{Digest, Sha256};
        let want = &Sha256::digest(inner)[..4];
        assert_eq!(parsed.advertisement_hash, want);
    }

    #[test]
    fn inner_roundtrip_with_psm() {
        let endpoint_id = *b"5SLA";
        let inner = build_inner_advertisement(endpoint_id, "Joe's Pixel 9 Pro XL", 0x0083);
        let d = parse_inner_advertisement(&inner).expect("inner parses");
        assert_eq!(d.endpoint_id, endpoint_id);
        assert_eq!(d.device_name, "Joe's Pixel 9 Pro XL");
        assert_eq!(d.device_type, 3); // DEVICE_TYPE_LAPTOP, as the builder sets
        assert_eq!(d.psm, 0x0083);
    }

    #[test]
    fn inner_roundtrip_without_psm() {
        let endpoint_id = *b"ABCD";
        let inner = build_inner_advertisement(endpoint_id, "Pixel", 0);
        let d = parse_inner_advertisement(&inner).expect("inner parses");
        assert_eq!(d.endpoint_id, endpoint_id);
        assert_eq!(d.device_name, "Pixel");
        assert_eq!(d.psm, 0);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_inner_advertisement(&[0u8; 4]).is_none());
        assert!(parse_advertisement_header(&[0u8; 3]).is_none());
    }
}
