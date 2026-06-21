//! The UKEY2-derived device-to-device (d2d) cipher session.
//!
//! rqs_lib historically kept the four UKEY2 keys and the two d2d sequence
//! counters as flat fields on [`super::InnerState`], mutated in place by the
//! `&mut self` receive loop in [`super::inbound`]. That works for the existing
//! single-task path, but the bandwidth-upgrade port ([`nearby_rs::bwu`]) needs a
//! [`nearby_rs::bwu::Cipher`], whose `encode`/`decode` take `&self` and must be
//! `Send + Sync` so the BWU actor can drive the same encryption from a different
//! task during the medium switch.
//!
//! [`UkeySession`] is that shared seam: the four write-once AES/HMAC keys plus
//! the two sequence counters behind atomics, wrapped in an `Arc`. Because the
//! **same** session instance is reused across the L2CAP -> WiFi swap, the d2d
//! sequence stays continuous (never resets) — the load-bearing invariant behind
//! the channel-drain handshake. The pure crypto here is byte-for-byte the same
//! as the old inline implementation; `inbound.rs` now delegates to it, so there
//! is a single source of truth.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use libaes::{Cipher as AesCipher, AES_256_KEY_LEN};
use prost::Message;
use sha2::Sha256;

use crate::securegcm::{DeviceToDeviceMessage, GcmMetadata, Type};
use crate::securemessage::{EncScheme, Header, HeaderAndBody, SecureMessage, SigScheme};
use crate::utils::gen_random;

type HmacSha256 = Hmac<Sha256>;

/// The shared UKEY2 d2d cipher: write-once keys + the two monotonic sequence
/// counters. Cheap to clone via `Arc`; the same instance is handed to both the
/// existing receive loop and (after the upgrade) the BWU layer so the sequence
/// never resets across the medium switch.
#[derive(Debug)]
pub struct UkeySession {
    /// AES-256 key for OUR outbound frames (the "server" role keys).
    encrypt_key: [u8; AES_256_KEY_LEN],
    /// HMAC-SHA256 key for OUR outbound frames.
    send_hmac_key: Vec<u8>,
    /// AES-256 key for the peer's inbound frames.
    decrypt_key: [u8; AES_256_KEY_LEN],
    /// HMAC-SHA256 key for the peer's inbound frames.
    recv_hmac_key: Vec<u8>,
    /// Outbound counter (our TX). Pre-increment: the first frame is seq=1.
    server_seq: AtomicI32,
    /// Inbound counter (peer TX). Pre-increment: the first frame is seq=1.
    client_seq: AtomicI32,
}

impl UkeySession {
    /// Build a session from the four derived UKEY2 keys. The AES keys must be at
    /// least [`AES_256_KEY_LEN`] (32) bytes — UKEY2 derives exactly that.
    /// Sequence counters start at 0, so the first frame each direction is seq=1
    /// (matching the historical `get_*_seq_inc` pre-increment semantics).
    pub fn new(
        encrypt_key: &[u8],
        send_hmac_key: &[u8],
        decrypt_key: &[u8],
        recv_hmac_key: &[u8],
    ) -> Result<Arc<Self>> {
        if encrypt_key.len() < AES_256_KEY_LEN || decrypt_key.len() < AES_256_KEY_LEN {
            return Err(anyhow!(
                "UKEY2 AES keys too short: encrypt={} decrypt={} (need {AES_256_KEY_LEN})",
                encrypt_key.len(),
                decrypt_key.len()
            ));
        }
        Ok(Arc::new(Self {
            encrypt_key: encrypt_key[..AES_256_KEY_LEN].try_into().unwrap(),
            send_hmac_key: send_hmac_key.to_vec(),
            decrypt_key: decrypt_key[..AES_256_KEY_LEN].try_into().unwrap(),
            recv_hmac_key: recv_hmac_key.to_vec(),
            server_seq: AtomicI32::new(0),
            client_seq: AtomicI32::new(0),
        }))
    }

    /// Advance and return the outbound sequence (pre-increment: 1, 2, 3, …).
    pub fn next_server_seq(&self) -> i32 {
        self.server_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Advance and return the inbound sequence (pre-increment: 1, 2, 3, …).
    pub fn next_client_seq(&self) -> i32 {
        self.client_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Current outbound sequence value (last assigned; 0 before the first frame).
    #[allow(dead_code)] // inspection API; used by tests and the upcoming BWU actor wiring
    pub fn server_seq(&self) -> i32 {
        self.server_seq.load(Ordering::SeqCst)
    }

    /// Current inbound sequence value (last assigned; 0 before the first frame).
    #[allow(dead_code)] // inspection API; used by tests and the upcoming BWU actor wiring
    pub fn client_seq(&self) -> i32 {
        self.client_seq.load(Ordering::SeqCst)
    }

    /// Encrypt one OfflineFrame's bytes into a wire `SecureMessage` (no length
    /// prefix — the transport adds the 4-byte big-endian frame length). `seq` is
    /// the d2d sequence number to stamp; `iv` is the 16-byte AES-CBC IV. Pure and
    /// deterministic given its inputs, so it can be unit-tested with a fixed IV.
    pub fn encode_payload(&self, frame_bytes: &[u8], seq: i32, iv: &[u8]) -> Vec<u8> {
        let d2d_msg = DeviceToDeviceMessage {
            sequence_number: Some(seq),
            message: Some(frame_bytes.to_vec()),
        };
        let msg_data = d2d_msg.encode_to_vec();

        let mut cipher = AesCipher::new_256(&self.encrypt_key);
        cipher.set_auto_padding(true);
        let encrypted = cipher.cbc_encrypt(iv, &msg_data);

        let hb = HeaderAndBody {
            body: encrypted,
            header: Header {
                encryption_scheme: EncScheme::Aes256Cbc.into(),
                signature_scheme: SigScheme::HmacSha256.into(),
                iv: Some(iv.to_vec()),
                public_metadata: Some(
                    GcmMetadata {
                        r#type: Type::DeviceToDeviceMessage.into(),
                        version: Some(1),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
        };

        let mut hmac = HmacSha256::new_from_slice(&self.send_hmac_key)
            .expect("HMAC-SHA256 accepts a key of any length");
        hmac.update(&hb.encode_to_vec());
        let signature = hmac.finalize().into_bytes().to_vec();

        SecureMessage {
            header_and_body: hb.encode_to_vec(),
            signature,
        }
        .encode_to_vec()
    }

    /// Decrypt one wire `SecureMessage`, returning `(declared_sequence_number,
    /// inner OfflineFrame bytes)`. Does NOT touch the inbound counter — the caller
    /// decides the sequence policy (the existing path logs the frame type before
    /// comparing; the [`nearby_rs::bwu::Cipher`] impl enforces it). Fails on a bad
    /// HMAC or malformed protobuf.
    pub fn decode_payload(&self, smsg: &SecureMessage) -> Result<(i32, Vec<u8>)> {
        let mut hmac = HmacSha256::new_from_slice(&self.recv_hmac_key)
            .expect("HMAC-SHA256 accepts a key of any length");
        hmac.update(&smsg.header_and_body);
        if hmac.finalize().into_bytes().as_slice() != smsg.signature.as_slice() {
            return Err(anyhow!("hmac!=signature"));
        }

        let header_and_body = HeaderAndBody::decode(&*smsg.header_and_body)?;
        let msg_data = header_and_body.body;

        let mut cipher = AesCipher::new_256(&self.decrypt_key);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &msg_data);

        let d2d_msg = DeviceToDeviceMessage::decode(&*decrypted)?;
        Ok((d2d_msg.sequence_number(), d2d_msg.message().to_vec()))
    }

    /// Encrypt one OfflineFrame's bytes, advancing the outbound sequence and
    /// generating a fresh random IV. Returns the wire `SecureMessage` bytes.
    pub fn encode_frame(&self, frame_bytes: &[u8]) -> Vec<u8> {
        let seq = self.next_server_seq();
        let iv = gen_random(16);
        self.encode_payload(frame_bytes, seq, &iv)
    }

    /// Decrypt one wire `SecureMessage`, advancing AND enforcing the inbound
    /// sequence. Returns the inner OfflineFrame bytes, or an error on HMAC
    /// failure, malformed protobuf, or a sequence mismatch.
    pub fn decode_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let smsg = SecureMessage::decode(ciphertext)?;
        let (declared, frame_bytes) = self.decode_payload(&smsg)?;
        let expect = self.next_client_seq();
        if declared != expect {
            return Err(anyhow!(
                "d2d sequence_number invalid ({declared} vs {expect})"
            ));
        }
        Ok(frame_bytes)
    }
}

/// The BWU port's cipher seam: bytes-in / bytes-out, `&self`, `Send + Sync`.
/// `encode`/`decode` operate on the inner `SecureMessage` (the [`StreamChannel`]
/// adds/strips the 4-byte length prefix), so they advance and enforce the d2d
/// sequence exactly as the existing receive path does.
///
/// [`StreamChannel`]: nearby_rs::bwu::StreamChannel
impl nearby_rs::bwu::Cipher for UkeySession {
    fn encode(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        Some(self.encode_frame(plaintext))
    }

    fn decode(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.decode_frame(ciphertext).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A symmetric loopback session: encrypt and decrypt with the same keys, so a
    // single instance can encode then decode its own frame. (The outbound and
    // inbound counters are independent, so both read 1 on the first frame.)
    fn loopback_session() -> Arc<UkeySession> {
        let aes = [7u8; AES_256_KEY_LEN];
        let mac = [9u8; 32];
        UkeySession::new(&aes, &mac, &aes, &mac).unwrap()
    }

    #[test]
    fn round_trips_a_frame() {
        let s = loopback_session();
        let frame = b"hello quick share".to_vec();
        let wire = s.encode_frame(&frame);
        let back = s.decode_frame(&wire).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn sequence_pre_increments_and_is_stamped() {
        let s = loopback_session();
        // First outbound frame carries d2d sequence_number == 1.
        let wire = s.encode_frame(b"f1");
        assert_eq!(s.server_seq(), 1);
        let smsg = SecureMessage::decode(wire.as_slice()).unwrap();
        let (declared, _) = s.decode_payload(&smsg).unwrap();
        assert_eq!(declared, 1);
    }

    #[test]
    fn two_counters_advance_independently() {
        let s = loopback_session();
        // Three sends advance only the server counter.
        for _ in 0..3 {
            let _ = s.encode_frame(b"x");
        }
        assert_eq!(s.server_seq(), 3);
        assert_eq!(s.client_seq(), 0);
        // A decode advances only the client counter; it must match the stamped
        // sequence (1), which equals the matching outbound frame's sequence.
        let wire = {
            let one = loopback_session();
            one.encode_frame(b"first")
        };
        let back = s.decode_frame(&wire).unwrap();
        assert_eq!(back, b"first");
        assert_eq!(s.client_seq(), 1);
        assert_eq!(s.server_seq(), 3);
    }

    #[test]
    fn rejects_out_of_order_sequence() {
        let s = loopback_session();
        // Encode at server_seq=1, but bump the client counter so decode expects 2.
        let wire = s.encode_frame(b"f1");
        s.next_client_seq(); // client now at 1; next decode expects 2
        let err = s.decode_frame(&wire);
        assert!(err.is_err(), "stale sequence must be rejected");
    }

    #[test]
    fn cipher_trait_round_trips() {
        use nearby_rs::bwu::Cipher;
        let s = loopback_session();
        let frame = b"via the Cipher trait".to_vec();
        let wire = Cipher::encode(&*s, &frame).expect("encode");
        let back = Cipher::decode(&*s, &wire).expect("decode");
        assert_eq!(back, frame);
    }

    #[test]
    fn cipher_trait_decode_returns_none_on_tamper() {
        use nearby_rs::bwu::Cipher;
        let s = loopback_session();
        let mut wire = Cipher::encode(&*s, b"tamper me").expect("encode");
        // Flip a byte in the ciphertext body so the HMAC check fails.
        let n = wire.len();
        wire[n / 2] ^= 0xFF;
        assert!(Cipher::decode(&*s, &wire).is_none());
    }

    #[test]
    fn rejects_short_aes_key() {
        let short = [0u8; 16];
        let mac = [0u8; 32];
        assert!(UkeySession::new(&short, &mac, &short, &mac).is_err());
    }
}
