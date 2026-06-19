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

use super::blea2::build_inner_advertisement;
use super::build_advertisement_header;

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

#[cfg(test)]
mod tests {
    use super::*;

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
