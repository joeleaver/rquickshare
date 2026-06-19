// Nearby Connections BLE "mode 3" advertisement header + service-id bloom filter.
//
// We broadcast this 17-byte header under the 0xFEF3 service data; the sender then
// GATT-reads our full inner BleAdvertisement and, seeing a non-zero PSM, opens an
// L2CAP CoC (gated by the phone's server-controlled kEnableBleL2cap flag).
//
// Layout (V2, 17 bytes with PSM) — google/nearby
// connections/implementation/mediums/ble/ble_advertisement_header.cc:
//   [0]      version(3)<<5 | ext_adv(1)<<4 | num_slots(4)   (V2,ext=0,slots=1 => 0x41)
//   [1..11]  service_id_bloom_filter (10 bytes / 80 bits)
//   [11..15] advertisement_hash (SHA256[:4]; dedup key, NOT validated by sender)
//   [15..17] L2CAP PSM, big-endian

use rand::Rng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const BLOOM_BITS: i64 = 80;
const BLOOM_NUM_HASHES: i32 = 5;

#[inline]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    k
}

/// MurmurHash3_x64_128 → (h1, h2). The bloom filter uses the low 64 bits (h1).
fn murmur3_x64_128(data: &[u8], seed: u32) -> (u64, u64) {
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;
    let mut h1 = seed as u64;
    let mut h2 = seed as u64;

    let nblocks = data.len() / 16;
    for i in 0..nblocks {
        let o = i * 16;
        let mut k1 = u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
        let mut k2 = u64::from_le_bytes(data[o + 8..o + 16].try_into().unwrap());

        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
    }

    let tail = &data[nblocks * 16..];
    let tl = tail.len();
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;
    // C-style fallthrough replicated via descending length checks.
    if tl >= 15 { k2 ^= (tail[14] as u64) << 48; }
    if tl >= 14 { k2 ^= (tail[13] as u64) << 40; }
    if tl >= 13 { k2 ^= (tail[12] as u64) << 32; }
    if tl >= 12 { k2 ^= (tail[11] as u64) << 24; }
    if tl >= 11 { k2 ^= (tail[10] as u64) << 16; }
    if tl >= 10 { k2 ^= (tail[9] as u64) << 8; }
    if tl >= 9 {
        k2 ^= tail[8] as u64;
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }
    if tl >= 8 { k1 ^= (tail[7] as u64) << 56; }
    if tl >= 7 { k1 ^= (tail[6] as u64) << 48; }
    if tl >= 6 { k1 ^= (tail[5] as u64) << 40; }
    if tl >= 5 { k1 ^= (tail[4] as u64) << 32; }
    if tl >= 4 { k1 ^= (tail[3] as u64) << 24; }
    if tl >= 3 { k1 ^= (tail[2] as u64) << 16; }
    if tl >= 2 { k1 ^= (tail[1] as u64) << 8; }
    if tl >= 1 {
        k1 ^= tail[0] as u64;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    let len = data.len() as u64;
    h1 ^= len;
    h2 ^= len;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}

/// Add one service-id string to an 80-bit (10-byte) bloom filter, matching
/// google/nearby bloom_filter.cc (Kirsch-Mitzenmacher double hashing).
fn bloom_add(filter: &mut [u8; 10], input: &[u8]) {
    let (h1, _h2) = murmur3_x64_128(input, 0);
    let hash1 = (h1 & 0xFFFF_FFFF) as u32 as i32;
    let hash2 = ((h1 >> 32) & 0xFFFF_FFFF) as u32 as i32;
    for i in 1..=BLOOM_NUM_HASHES {
        let mut combined = hash1.wrapping_add(i.wrapping_mul(hash2));
        if combined < 0 {
            combined = !combined; // bitwise NOT, per Guava/Nearby
        }
        let pos = (combined as i64 % BLOOM_BITS) as usize;
        filter[pos / 8] |= 1 << (pos % 8); // LSB-first within byte
    }
}

/// Build the 17-byte V2 BleAdvertisementHeader to broadcast under 0xFEF3.
/// `inner_advertisement` is the full BleAdvertisement served over GATT (its
/// SHA256[:4] becomes the advert hash / dedup key).
pub fn build_advertisement_header(psm: u16, inner_advertisement: &[u8]) -> Vec<u8> {
    // V2 (2<<5), ext_adv=0, num_slots=1.
    let byte0: u8 = (2u8 << 5) | (1 & 0x0F);

    // Bloom filter: random 128-byte salt (anonymization) + the service id string.
    // "NearbySharing" must be possibly-contained so the sender bothers to fetch.
    let mut filter = [0u8; 10];
    let salt: [u8; 128] = rand::rng().random();
    bloom_add(&mut filter, &salt);
    bloom_add(&mut filter, b"NearbySharing");

    let hash = Sha256::digest(inner_advertisement);

    let mut h = Vec::with_capacity(17);
    h.push(byte0);
    h.extend_from_slice(&filter);
    h.extend_from_slice(&hash[..4]);
    h.extend_from_slice(&psm.to_be_bytes());
    h
}

/// GATT advertisement characteristic UUID for a slot:
/// base 00000000-0000-3000-8000-000000000000 OR'd with the slot number.
pub fn advertisement_uuid(slot: u8) -> Uuid {
    Uuid::from_u64_pair(0x0000_0000_0000_3000, 0x8000_0000_0000_0000 | slot as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur_empty_is_zero() {
        // MurmurHash3_x64_128("", seed=0) == (0, 0).
        assert_eq!(murmur3_x64_128(b"", 0), (0, 0));
    }

    #[test]
    fn bloom_contains_nearbysharing_bits() {
        // The exact bits "NearbySharing" sets must be present (sender checks these).
        let mut reference = [0u8; 10];
        bloom_add(&mut reference, b"NearbySharing");
        assert_ne!(reference, [0u8; 10], "bloom must set bits for the service id");

        // A full header (salt + service id) must still contain all reference bits.
        let header = build_advertisement_header(0x0083, b"inner");
        let filter = &header[1..11];
        for i in 0..10 {
            assert_eq!(filter[i] & reference[i], reference[i], "missing service-id bit in byte {i}");
        }
    }

    #[test]
    fn header_shape() {
        let h = build_advertisement_header(0x0083, b"inner advert bytes");
        assert_eq!(h.len(), 17);
        assert_eq!(h[0], 0x41); // V2, ext=0, slots=1
        assert_eq!(&h[15..17], &[0x00, 0x83]); // PSM big-endian
    }
}
