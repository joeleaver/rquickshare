//! Bridges rqs_lib's async [`Transport`](super::inbound::Transport) to a
//! nearby-rs blocking [`EndpointChannel`](nearby_rs::bwu::EndpointChannel) so the
//! BWU [`BwuActor`](nearby_rs::bwu::BwuActor) can co-own the channel during the
//! medium upgrade.
//!
//! nearby-rs channels are a faithful port of Google's blocking `InputStream`/
//! `OutputStream` model: [`StreamChannel`] does 4-byte big-endian length framing
//! and (when a [`Cipher`] is installed) encryption, over a **blocking**
//! [`DuplexStream`]. rqs_lib's transport is tokio async. [`TransportBridge`] is
//! the glue: two pump tasks move bytes between the async transport and a blocking
//! buffer the `DuplexStream` methods operate on.
//!
//! The framing here is byte-for-byte rqs_lib's existing wire format
//! (`InboundRequest::_handle`/`send_frame`: 4-byte BE length + body), and the
//! [`Cipher`] is the shared [`UkeySession`] — so a `StreamChannel` built here is
//! wire-compatible with the proven receive path. This is the channel the inverted
//! (`QS_BWU_ACTOR`) receive loop reads/writes and registers with the actor.
//!
//! Staged for the `QS_BWU_ACTOR` wiring (a later step); only the tests exercise it
//! today, hence the module-level dead-code allowance.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use nearby_rs::bwu::{
    BaseBwuHandler, BwuActor, BwuConfig, BwuHandle, BwuHandler, DuplexStream, SoftAp, StreamChannel,
    WifiHotspotBwuHandler, WifiLanBwuHandler,
};
use nearby_rs::frames::Exception;
use nearby_rs::mediums::Medium;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::UkeySession;

#[derive(Default)]
struct Inbound {
    buf: VecDeque<u8>,
    closed: bool,
}

/// A blocking [`DuplexStream`] over an async tokio transport. A reader pump fills
/// `inbound` (which `read_exact` blocks on); `write_all` enqueues onto an mpsc the
/// writer pump drains to the transport. Mirrors the in-memory `Pipe` nearby-rs
/// ships for tests, but one side is a real async socket.
pub struct TransportBridge {
    inbound: Mutex<Inbound>,
    inbound_cond: Condvar,
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    closed: AtomicBool,
}

impl DuplexStream for TransportBridge {
    fn read_exact(&self, buf: &mut [u8]) -> Result<(), Exception> {
        let mut state = self.inbound.lock().unwrap();
        let mut filled = 0;
        while filled < buf.len() {
            if state.buf.is_empty() {
                if state.closed {
                    // EOF / transport closed before the requested bytes — `kNoData`.
                    return Err(Exception::NoData);
                }
                state = self.inbound_cond.wait(state).unwrap();
                continue;
            }
            while filled < buf.len() {
                match state.buf.pop_front() {
                    Some(byte) => {
                        buf[filled] = byte;
                        filled += 1;
                    }
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn write_all(&self, buf: &[u8]) -> Result<(), Exception> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Exception::Io);
        }
        // Non-blocking hand-off to the writer pump; the pump does the await.
        self.outbound_tx.send(buf.to_vec()).map_err(|_| Exception::Io)
    }

    fn flush(&self) -> Result<(), Exception> {
        // The writer pump flushes the transport after every chunk it writes.
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut state = self.inbound.lock().unwrap();
        state.closed = true;
        self.inbound_cond.notify_all();
    }
}

/// A [`StreamChannel`] over a [`TransportBridge`], plus the pump tasks that drive
/// it. Hold this for the life of the channel; dropping it aborts the pumps.
pub struct EndpointChannelBridge {
    /// The channel to register with the actor and read/write the transfer through.
    pub channel: Arc<StreamChannel>,
    reader_pump: JoinHandle<()>,
    writer_pump: JoinHandle<()>,
}

impl EndpointChannelBridge {
    /// Build a `StreamChannel` over `transport`, encrypted by the shared
    /// `session`, reporting `medium`. Spawns the two pump tasks on the current
    /// Tokio runtime (so call from within one).
    pub fn new<T>(
        transport: T,
        session: Arc<UkeySession>,
        service_id: impl Into<String>,
        medium: Medium,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::build(transport, Some(session), service_id, medium)
    }

    /// Build a `StreamChannel` over `transport` with **no** cipher installed —
    /// reads/writes are plaintext `[4B len][frame]` until a later
    /// [`EndpointChannel::enable_encryption`](nearby_rs::bwu::EndpointChannel) call
    /// turns encryption on. Used by the live `QS_BWU_ACTOR` receive path, which
    /// carries the plaintext UKEY2 handshake on the channel and only installs the
    /// shared [`UkeySession`] cipher once key derivation completes.
    pub fn new_plaintext<T>(transport: T, service_id: impl Into<String>, medium: Medium) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::build(transport, None, service_id, medium)
    }

    fn build<T>(
        transport: T,
        session: Option<Arc<UkeySession>>,
        service_id: impl Into<String>,
        medium: Medium,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(transport);
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let bridge = Arc::new(TransportBridge {
            inbound: Mutex::new(Inbound::default()),
            inbound_cond: Condvar::new(),
            outbound_tx,
            closed: AtomicBool::new(false),
        });

        // Reader pump: async transport -> the blocking inbound buffer.
        let reader_pump = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match rd.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            // EOF or error: mark closed so a blocked read_exact returns NoData.
                            let mut state = bridge.inbound.lock().unwrap();
                            state.closed = true;
                            bridge.inbound_cond.notify_all();
                            break;
                        }
                        Ok(n) => {
                            let mut state = bridge.inbound.lock().unwrap();
                            state.buf.extend(&buf[..n]);
                            bridge.inbound_cond.notify_all();
                        }
                    }
                }
            })
        };

        // Writer pump: the outbound queue -> async transport.
        let writer_pump = tokio::spawn(async move {
            while let Some(chunk) = outbound_rx.recv().await {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
                if wr.flush().await.is_err() {
                    break;
                }
            }
        });

        let channel = Arc::new(StreamChannel::new(service_id, "bwu", medium, bridge));
        if let Some(session) = session {
            channel.enable_encryption(session);
        }

        Self {
            channel,
            reader_pump,
            writer_pump,
        }
    }
}

impl Drop for EndpointChannelBridge {
    fn drop(&mut self) {
        // Stop pumping; the channel/bridge are dropped with us.
        self.reader_pump.abort();
        self.writer_pump.abort();
    }
}

/// Owns a running [`BwuActor`] + its medium handlers, and exposes the
/// [`BwuHandle`] the inverted (`QS_BWU_ACTOR`) receive loop drives. beamish is the
/// BWU **initiator**: the WIFI_LAN handler binds a `TcpListener` (on `bind_ip`)
/// and advertises `advertise_ip`; the optional WIFI_HOTSPOT handler stands up a
/// SoftAP via the injected [`SoftAp`] seam, binds on the AP gateway, and advertises
/// the hotspot credentials. Each handler's accept loop posts dialed sockets back to
/// the actor via the connection sink. Dropping the session aborts the actor task.
pub struct BwuSession {
    /// Drive the actor from the receive loop: `connection_initiated`,
    /// `connection_accepted`, `register_channel`, `initiate_bwu`, `incoming_frame`,
    /// `is_upgrade_ongoing`, `get_upgraded_channel`, …
    pub handle: BwuHandle,
    actor_task: JoinHandle<()>,
}

impl BwuSession {
    /// Build the actor with a WIFI_LAN handler (and, when `softap` is provided, a
    /// WIFI_HOTSPOT handler) and spawn it on the current Tokio runtime.
    /// `local_endpoint_id` is our Nearby endpoint id; `bind_ip` is what the WIFI_LAN
    /// upgrade `TcpListener` binds to (`0.0.0.0` in prod) and `advertise_ip` is the
    /// routable LAN address put in the WIFI_LAN `UPGRADE_PATH_AVAILABLE` offer.
    ///
    /// `softap` is the platform SoftAP seam (e.g. `NmSoftAp`). When `Some`, a
    /// [`WifiHotspotBwuHandler`] is registered under [`Medium::WifiHotspot`] in
    /// addition to WIFI_LAN, so the offer policy in `l2cap.rs` can initiate either
    /// medium; the hotspot handler derives its own bind/gateway from
    /// [`SoftAp::start`], so `bind_ip`/`advertise_ip` don't apply to it. `None` =
    /// WIFI_LAN only (the default, hardware-agnostic path).
    ///
    /// **Runtime requirement:** call this on a **multi-thread** Tokio runtime. The
    /// BWU handshake does blocking channel I/O on the actor task — most notably the
    /// single drain `read()` in nearby-rs's `process_safe_to_close` — while the
    /// [`EndpointChannelBridge`] reader/writer pumps run as separate tasks. On a
    /// `current_thread` runtime the blocking read would starve the pumps and
    /// deadlock. beamish's default `#[tokio::main]` runtime is multi-thread, so this
    /// holds; a dedicated-thread deployment must give the pumps their own runtime.
    pub fn spawn(
        local_endpoint_id: impl Into<String>,
        bind_ip: Ipv4Addr,
        advertise_ip: Ipv4Addr,
        softap: Option<Arc<dyn SoftAp>>,
    ) -> Self {
        // channel() first so each handler's accept loop has a sink to the actor
        // before the actor exists.
        let (handle, rx) = BwuActor::channel(32);
        let mut handlers: HashMap<Medium, Box<dyn BwuHandler>> = HashMap::new();

        let wifi = WifiLanBwuHandler::with_endpoint(handle.connection_sink(), bind_ip, advertise_ip);
        handlers.insert(Medium::WifiLan, Box::new(BaseBwuHandler::new(wifi)));

        if let Some(softap) = softap {
            let hotspot = WifiHotspotBwuHandler::new(softap, handle.connection_sink());
            handlers.insert(Medium::WifiHotspot, Box::new(BaseBwuHandler::new(hotspot)));
        }

        let actor = BwuActor::build(rx, handlers, BwuConfig::default(), local_endpoint_id);
        let actor_task = tokio::spawn(actor.run());
        Self { handle, actor_task }
    }
}

impl Drop for BwuSession {
    fn drop(&mut self) {
        self.actor_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libaes::AES_256_KEY_LEN;
    use nearby_rs::bwu::{EndpointChannel, Pipe};
    use nearby_rs::frames::Exception;
    use prost::Message;

    use crate::securemessage::SecureMessage;

    // A symmetric loopback session (encrypt == decrypt keys) so one channel can
    // round-trip its own frame.
    fn loopback_session() -> Arc<UkeySession> {
        let aes = [7u8; AES_256_KEY_LEN];
        let mac = [9u8; 32];
        UkeySession::new(&aes, &mac, &aes, &mac).unwrap()
    }

    #[test]
    fn stream_channel_with_ukey_session_round_trips() {
        // A StreamChannel over an in-memory Pipe, encrypted by UkeySession, must
        // read back exactly what it wrote (proves the Cipher seam + 4B framing).
        let session = loopback_session();
        let pipe = Pipe::new();
        let sc = StreamChannel::new("svc", "bwu", Medium::BleL2cap, pipe);
        sc.enable_encryption(session);

        let frame = b"a quick share offline frame".to_vec();
        assert_eq!(sc.write(&frame), Exception::Success);
        assert_eq!(sc.read().unwrap(), frame);
    }

    #[test]
    fn stream_channel_write_is_rqs_wire_faithful() {
        // StreamChannel.write must produce exactly rqs_lib's wire format:
        // [4B BE len][SecureMessage], where the SecureMessage is a UKEY2 d2d frame
        // stamped seq=1 and decryptable with the same keys — i.e. byte-for-byte
        // what `encrypt_and_send` + `send_frame` emit today.
        let session = loopback_session();
        let pipe = Pipe::new();
        let sc = StreamChannel::new("svc", "bwu", Medium::BleL2cap, pipe.clone());
        sc.enable_encryption(session);

        let frame = b"hello wire".to_vec();
        assert_eq!(sc.write(&frame), Exception::Success);

        // Drain the raw framed bytes straight off the pipe (the channel didn't read).
        let mut len_buf = [0u8; 4];
        DuplexStream::read_exact(&*pipe, &mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        DuplexStream::read_exact(&*pipe, &mut body).unwrap();

        // The body is a SecureMessage decryptable to our frame at d2d seq 1.
        let smsg = SecureMessage::decode(body.as_slice()).expect("body is a SecureMessage");
        let peer = loopback_session();
        let (seq, inner) = peer.decode_payload(&smsg).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(inner, frame);
    }

    #[tokio::test]
    async fn transport_bridge_pumps_frames_both_ways() {
        // Build the bridge over one end of a tokio duplex; the test plays the peer
        // on the other end. Channel read/write are blocking, so run them on a
        // blocking thread while the async peer side drives the socket.
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let session = loopback_session();
        let ecb = EndpointChannelBridge::new(ours, session, "svc", Medium::BleL2cap);
        let channel = ecb.channel.clone();

        // us -> peer: blocking write reaches the socket as [len][SecureMessage].
        let frame = b"ping over the bridge".to_vec();
        let w = tokio::task::spawn_blocking({
            let c = channel.clone();
            let f = frame.clone();
            move || c.write(&f)
        });
        let mut len_buf = [0u8; 4];
        peer.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(w.await.unwrap(), Exception::Success);

        let peer_session = loopback_session();
        let smsg = SecureMessage::decode(body.as_slice()).unwrap();
        assert_eq!(peer_session.decode_payload(&smsg).unwrap(), (1, frame));

        // peer -> us: a seq=1 frame the channel's blocking read decrypts.
        let frame2 = b"pong over the bridge".to_vec();
        let enc = peer_session.encode_payload(&frame2, 1, &[0u8; 16]);
        peer.write_all(&(enc.len() as u32).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(&enc).await.unwrap();
        peer.flush().await.unwrap();

        let got = tokio::task::spawn_blocking(move || channel.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, frame2);
    }

    #[tokio::test]
    async fn bwu_session_emits_encrypted_wifi_lan_offer_on_the_registered_channel() {
        use crate::location_nearby_connections as lnc;

        // Our channel over one end of a duplex; the test plays the phone on the other.
        let session = loopback_session();
        let (ours, mut peer) = tokio::io::duplex(64 * 1024);
        let ecb = EndpointChannelBridge::new(ours, session, "svc", Medium::BleL2cap);
        let channel = ecb.channel.clone();

        // Stand up the actor (initiator) and drive it to offer a WIFI_LAN upgrade
        // on the registered channel — the exact sequence the live receive loop uses.
        let bwu = BwuSession::spawn("LOCL", Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, None);
        let ep = "PEER";
        bwu.handle.connection_initiated(ep, false, false).await;
        bwu.handle.connection_accepted(ep).await;
        bwu.handle.register_channel(ep, channel).await;
        bwu.handle.initiate_bwu(ep, Medium::WifiLan).await;
        assert!(bwu.handle.is_upgrade_ongoing(ep).await);

        // The actor wrote an ENCRYPTED UPGRADE_PATH_AVAILABLE on the channel, which
        // the bridge pumped to the peer as [4B len][SecureMessage @ seq 1].
        let mut len_buf = [0u8; 4];
        peer.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        peer.read_exact(&mut body).await.unwrap();

        let peer_session = loopback_session();
        let smsg = SecureMessage::decode(body.as_slice()).unwrap();
        let (seq, inner) = peer_session.decode_payload(&smsg).unwrap();
        assert_eq!(seq, 1);

        // …and it decodes as a WIFI_LAN UPGRADE_PATH_AVAILABLE offer.
        let frame = lnc::OfflineFrame::decode(inner.as_slice()).unwrap();
        let v1 = frame.v1.unwrap();
        assert_eq!(
            v1.r#type(),
            lnc::v1_frame::FrameType::BandwidthUpgradeNegotiation
        );
        let neg = v1.bandwidth_upgrade_negotiation.unwrap();
        use lnc::bandwidth_upgrade_negotiation_frame as bwu_frame;
        assert_eq!(neg.event_type(), bwu_frame::EventType::UpgradePathAvailable);
        assert_eq!(
            neg.upgrade_path_info.unwrap().medium(),
            bwu_frame::upgrade_path_info::Medium::WifiLan
        );
    }

    // -- the offline full-upgrade de-risk simulation ------------------------

    /// Read one `[4B BE len][SecureMessage]` frame off the peer end of the OLD
    /// channel duplex and decrypt it with `session`, returning the inner OfflineFrame
    /// bytes. Uses `decode_frame` (not `decode_payload`), so it advances AND enforces
    /// the phone's inbound sequence exactly as a real Pixel does — a misordered or
    /// reset frame from our side fails the `.unwrap()` here rather than passing
    /// silently.
    async fn phone_read_old(
        peer: &mut tokio::io::DuplexStream,
        session: &Arc<UkeySession>,
    ) -> Vec<u8> {
        let mut len_buf = [0u8; 4];
        peer.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        peer.read_exact(&mut body).await.unwrap();
        session.decode_frame(&body).unwrap()
    }

    /// Encrypt `frame_bytes` with `session` (advancing its outbound seq) and write
    /// it `[4B BE len][SecureMessage]` onto the peer end of the OLD channel — the
    /// phone sending an encrypted BWU frame back to us.
    async fn phone_write_old(
        peer: &mut tokio::io::DuplexStream,
        session: &Arc<UkeySession>,
        frame_bytes: &[u8],
    ) {
        let wire = session.encode_frame(frame_bytes);
        peer.write_all(&(wire.len() as u32).to_be_bytes())
            .await
            .unwrap();
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();
    }

    /// Blocking-read one decrypted OfflineFrame off OUR end of the OLD channel
    /// (the consumer's read), decoded as a nearby-rs `pb::OfflineFrame`.
    async fn consumer_read_bwu(channel: &Arc<StreamChannel>) -> nearby_rs::proto::OfflineFrame {
        let c = channel.clone();
        let bytes = tokio::task::spawn_blocking(move || c.read())
            .await
            .unwrap()
            .expect("a decrypted BWU frame on the old channel");
        nearby_rs::proto::OfflineFrame::decode(bytes.as_slice()).unwrap()
    }

    /// The full faithful BWU upgrade — UPGRADE_PATH_AVAILABLE → CLIENT_INTRODUCTION
    /// → LAST_WRITE → SAFE_TO_CLOSE → channel swap → `get_upgraded_channel` — driven
    /// end-to-end through the real rqs_lib bridge stack (`BwuSession` actor +
    /// `EndpointChannelBridge` + `UkeySession`) over a real TCP upgrade socket, with
    /// no phone. This de-risks the (Pixel-gated, invasive) live `l2cap.rs` inversion:
    /// it exercises the exact components, frame ordering, and the seq-continuity
    /// invariant the live path depends on, catching deadlocks/framing/seq bugs here.
    ///
    /// Roles, all played by this test:
    /// * **actor** (the spawned `BwuSession`) — co-owns the OLD channel; writes the
    ///   offer/LAST_WRITE/SAFE_TO_CLOSE on it, runs the new-channel handshake.
    /// * **phone** (the `peer` half of the OLD duplex + a real TCP dial) — decrypts
    ///   our offers and sends the plaintext CLIENT_INTRODUCTION on the new socket +
    ///   the encrypted LAST_WRITE/SAFE_TO_CLOSE replies on the old one.
    /// * **consumer** (this flow) — sole reader of the OLD channel; feeds the phone's
    ///   BWU replies to the actor via `incoming_frame` (the live receive loop's job).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn full_wifi_lan_upgrade_converges_through_bwu_session_over_real_tcp() {
        use nearby_rs::bwu::{ClientProxy, MediumBwuHandler, WifiLanBwuHandler};
        use nearby_rs::frames::{for_bwu_introduction, for_bwu_last_write, for_bwu_safe_to_close};

        let ep = "PEER";

        // Two UkeySession instances with the SAME (symmetric loopback) keys: `ours`
        // is the OLD channel's cipher; `phone` mirrors it so the simulated remote
        // can decrypt our offers and encrypt its replies at matching sequences.
        let ours = loopback_session();
        let phone = loopback_session();

        // OLD (L2CAP) channel over a tokio duplex; we play the phone on `peer`.
        let (old_io, mut peer) = tokio::io::duplex(64 * 1024);
        let ecb = EndpointChannelBridge::new(old_io, ours.clone(), "svc", Medium::BleL2cap);
        let old_channel = ecb.channel.clone();

        // Initiator: stand up the actor and OFFER a WIFI_LAN upgrade on the OLD
        // channel — the live receive loop's exact sequence.
        let bwu = BwuSession::spawn("LOCL", Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, None);
        // Baseline: no bandwidth change has happened yet, so the post-upgrade event
        // we assert later must be one this upgrade newly produced.
        assert!(
            bwu.handle.bandwidth_changed_events().await.is_empty(),
            "no bandwidth change should exist before the upgrade"
        );
        bwu.handle.connection_initiated(ep, false, false).await;
        bwu.handle.connection_accepted(ep).await;
        bwu.handle.register_channel(ep, old_channel.clone()).await;
        bwu.handle.initiate_bwu(ep, Medium::WifiLan).await;
        assert!(bwu.handle.is_upgrade_ongoing(ep).await);

        // PHONE: read the encrypted UPGRADE_PATH_AVAILABLE; pull out the dial creds.
        let info = {
            let inner = phone_read_old(&mut peer, &phone).await;
            nearby_rs::from_bytes(&inner)
                .unwrap()
                .v1
                .unwrap()
                .bandwidth_upgrade_negotiation
                .unwrap()
                .upgrade_path_info
                .unwrap()
        };

        // PHONE: dial the advertised socket + send a PLAINTEXT CLIENT_INTRODUCTION on
        // the new WIFI_LAN channel (plaintext during the handshake — exactly the
        // proven l2cap.rs path), then read the ACK. Hold the socket open until the
        // end so the upgraded channel stays live.
        let responder = std::thread::spawn({
            let ep = ep.to_string();
            move || {
                let mut handler = WifiLanBwuHandler::new(Arc::new(|_| {}));
                let new_chan = handler
                    .create_upgraded_endpoint_channel(&ClientProxy::default(), "svc", &ep, &info)
                    .expect("phone dials the advertised WIFI_LAN socket");
                assert_eq!(
                    new_chan.write(&for_bwu_introduction(&ep, "", false)),
                    Exception::Success
                );
                new_chan
                    .read()
                    .expect("CLIENT_INTRODUCTION_ACK on the new channel");
                new_chan
            }
        });

        // The actor accepted the new socket, ran on_incoming_connection, and wrote
        // LAST_WRITE (encrypted) on the OLD channel. PHONE: read it, reply with its
        // own LAST_WRITE_TO_PRIOR_CHANNEL.
        let _our_last_write = phone_read_old(&mut peer, &phone).await;
        phone_write_old(&mut peer, &phone, &for_bwu_last_write()).await;

        // CONSUMER: read the phone's LAST_WRITE off the OLD channel + feed the actor.
        let frame = consumer_read_bwu(&old_channel).await;
        bwu.handle.incoming_frame(frame, ep, Medium::BleL2cap).await;

        // The actor wrote SAFE_TO_CLOSE (encrypted) on the OLD channel. PHONE: read
        // it, reply with SAFE_TO_CLOSE_PRIOR_CHANNEL.
        let _our_safe_to_close = phone_read_old(&mut peer, &phone).await;
        phone_write_old(&mut peer, &phone, &for_bwu_safe_to_close()).await;

        // CONSUMER: read the phone's SAFE_TO_CLOSE + feed the actor. Processing it
        // disables encryption on OLD, writes a plaintext DISCONNECTION, then does a
        // single drain read — closing our peer end lets that read return (EOF) so the
        // actor can close OLD and converge.
        let frame = consumer_read_bwu(&old_channel).await;
        bwu.handle.incoming_frame(frame, ep, Medium::BleL2cap).await;
        drop(peer);

        // Convergence: is_upgrade_ongoing flips false + a (ep, WifiLan) bandwidth
        // change is recorded.
        let mut converged = false;
        for _ in 0..300 {
            if !bwu.handle.is_upgrade_ongoing(ep).await {
                converged = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(converged, "the WIFI_LAN upgrade should converge");
        assert!(
            bwu.handle
                .bandwidth_changed_events()
                .await
                .iter()
                .any(|(id, m)| id == ep && *m == Medium::WifiLan),
            "a (PEER, WifiLan) bandwidth change should be recorded"
        );

        // The consumer retrieves the upgraded channel to continue the transfer on.
        let upgraded = bwu
            .handle
            .get_upgraded_channel(ep)
            .await
            .expect("the upgraded channel is retrievable after convergence");
        assert_eq!(upgraded.medium(), Medium::WifiLan);

        // The swap really happened: the registry returned a DIFFERENT channel Arc,
        // not the old one with a coincidentally-WifiLan medium.
        assert_ne!(
            Arc::as_ptr(&old_channel) as *const (),
            Arc::as_ptr(&upgraded) as *const (),
            "the upgraded channel must be a different Arc than the old one"
        );

        // The OLD channel was actually closed by the protocol (not merely abandoned):
        // a read now errors instead of blocking or returning data.
        let old_after = {
            let c = old_channel.clone();
            tokio::task::spawn_blocking(move || c.read()).await.unwrap()
        };
        assert!(
            old_after.is_err(),
            "the old channel must be closed after the upgrade"
        );

        // State at the swap point: the SHARED `ours` session carried all of the OLD
        // channel's encrypted traffic — three outbound (UPGRADE_PATH_AVAILABLE,
        // LAST_WRITE, SAFE_TO_CLOSE) and two inbound (the phone's LAST_WRITE +
        // SAFE_TO_CLOSE) — so its counters are 3/2, not reset.
        assert_eq!(ours.server_seq(), 3, "outbound seq preserved across the swap");
        assert_eq!(ours.client_seq(), 2, "inbound seq preserved across the swap");

        // SEQ CONTINUITY — the real proof, not just the counter snapshot. Install the
        // SAME `ours` session on the upgraded channel and exchange an encrypted frame
        // each way. The decrypts only succeed if the sequence CONTINUES across the
        // swap (out 3->4, in 2->3); a reset-to-1 would make the peer's `decode_frame`
        // reject the frame and the reads below would error. This is the historical
        // "6 vs 5" / 10s-stall invariant, exercised end-to-end over the real TCP
        // socket with no phone.
        let phone_new_chan = responder.join().unwrap();
        upgraded.enable_encryption(ours.clone());
        phone_new_chan.enable_encryption(phone.clone());

        // us -> phone, at the continued OUTBOUND seq 4.
        let payload = b"first payload after the WiFi upgrade".to_vec();
        let wrote = {
            let up = upgraded.clone();
            let p = payload.clone();
            tokio::task::spawn_blocking(move || up.write(&p))
                .await
                .unwrap()
        };
        assert_eq!(wrote, Exception::Success);
        assert_eq!(
            ours.server_seq(),
            4,
            "outbound seq continues (3 -> 4) on the new channel"
        );
        let phone_got = {
            let c = phone_new_chan.clone();
            tokio::task::spawn_blocking(move || c.read())
                .await
                .unwrap()
                .expect("phone decrypts our frame at the continued inbound seq (4)")
        };
        assert_eq!(phone_got, payload);

        // phone -> us, at its continued OUTBOUND seq 3 (our continued INBOUND seq 3).
        let reply = b"ack from the phone over WiFi".to_vec();
        {
            let c = phone_new_chan.clone();
            let r = reply.clone();
            tokio::task::spawn_blocking(move || c.write(&r))
                .await
                .unwrap();
        }
        let our_got = {
            let up = upgraded.clone();
            tokio::task::spawn_blocking(move || up.read())
                .await
                .unwrap()
                .expect("we decrypt the phone's frame at the continued inbound seq (3)")
        };
        assert_eq!(our_got, reply);
        assert_eq!(
            ours.client_seq(),
            3,
            "inbound seq continues (2 -> 3) on the new channel"
        );
    }

    /// The WIFI_HOTSPOT analogue of the WIFI_LAN upgrade above: when `BwuSession`
    /// is given a [`SoftAp`], it registers a `WifiHotspotBwuHandler` and an
    /// `initiate_bwu(ep, WifiHotspot)` runs the SAME full handshake — offer →
    /// CLIENT_INTRODUCTION → LAST_WRITE → SAFE_TO_CLOSE → swap — converging to a
    /// `Medium::WifiHotspot` channel with the d2d sequence preserved. Uses
    /// [`FakeSoftAp`] (loopback creds) so the AP bring-up is a no-op and the phone
    /// dials `127.0.0.1` over real TCP — the platform `NmSoftAp` is the only piece
    /// this can't exercise without radios. Proves the offer-policy wiring (task #18)
    /// can drive a hotspot upgrade end-to-end through the bridge stack.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn full_wifi_hotspot_upgrade_converges_through_bwu_session_over_real_tcp() {
        use nearby_rs::bwu::{
            ClientProxy, FakeSoftAp, MediumBwuHandler, SoftAp, WifiHotspotBwuHandler,
        };
        use nearby_rs::frames::{for_bwu_introduction, for_bwu_last_write, for_bwu_safe_to_close};

        let ep = "PEER";
        let ours = loopback_session();
        let phone = loopback_session();

        // OLD (L2CAP) channel; we play the phone on `peer`.
        let (old_io, mut peer) = tokio::io::duplex(64 * 1024);
        let ecb = EndpointChannelBridge::new(old_io, ours.clone(), "svc", Medium::BleL2cap);
        let old_channel = ecb.channel.clone();

        // Initiator: spawn the actor WITH a SoftAP seam, then offer a WIFI_HOTSPOT
        // upgrade on the OLD channel.
        let softap: Arc<dyn SoftAp> = Arc::new(FakeSoftAp::new());
        let bwu = BwuSession::spawn("LOCL", Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, Some(softap));
        bwu.handle.connection_initiated(ep, false, false).await;
        bwu.handle.connection_accepted(ep).await;
        bwu.handle.register_channel(ep, old_channel.clone()).await;
        bwu.handle.initiate_bwu(ep, Medium::WifiHotspot).await;
        assert!(bwu.handle.is_upgrade_ongoing(ep).await);

        // PHONE: read the encrypted WIFI_HOTSPOT UPGRADE_PATH_AVAILABLE + creds.
        let info = {
            let inner = phone_read_old(&mut peer, &phone).await;
            nearby_rs::from_bytes(&inner)
                .unwrap()
                .v1
                .unwrap()
                .bandwidth_upgrade_negotiation
                .unwrap()
                .upgrade_path_info
                .unwrap()
        };
        assert_eq!(
            info.medium(),
            nearby_rs::proto::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium::WifiHotspot
        );
        // Pin the spike-validated wire contract: the Pixel accepted the offer because
        // these exact fields were present. A future regression that drops/zeroes any
        // of them must fail here, not silently in the field on a phone.
        assert_eq!(
            info.supports_client_introduction_ack,
            Some(true),
            "offer must request a CLIENT_INTRODUCTION ack (matches the spike)"
        );
        let creds = info
            .wifi_hotspot_credentials
            .as_ref()
            .expect("the offer must carry WifiHotspotCredentials");
        assert!(!creds.ssid().is_empty(), "ssid present");
        assert!(!creds.password().is_empty(), "password present");
        assert!(creds.port() > 0, "port present");
        assert!(
            creds.gateway().parse::<std::net::Ipv4Addr>().is_ok(),
            "gateway parses to an IPv4 address"
        );
        assert!(creds.frequency.is_some(), "frequency set");

        // PHONE: join the AP (FakeSoftAp = no-op) + dial the advertised socket via the
        // responder side of the hotspot handler, send a plaintext CLIENT_INTRODUCTION.
        let responder = std::thread::spawn({
            let ep = ep.to_string();
            move || {
                let mut handler =
                    WifiHotspotBwuHandler::new(Arc::new(FakeSoftAp::new()), Arc::new(|_| {}));
                let new_chan = handler
                    .create_upgraded_endpoint_channel(&ClientProxy::default(), "svc", &ep, &info)
                    .expect("phone joins the SoftAP + dials the advertised socket");
                assert_eq!(new_chan.medium(), Medium::WifiHotspot);
                assert_eq!(
                    new_chan.write(&for_bwu_introduction(&ep, "", false)),
                    Exception::Success
                );
                new_chan
                    .read()
                    .expect("CLIENT_INTRODUCTION_ACK on the new channel");
                new_chan
            }
        });

        // OLD-channel teardown handshake, identical to WIFI_LAN.
        let _our_last_write = phone_read_old(&mut peer, &phone).await;
        phone_write_old(&mut peer, &phone, &for_bwu_last_write()).await;
        let frame = consumer_read_bwu(&old_channel).await;
        bwu.handle.incoming_frame(frame, ep, Medium::BleL2cap).await;

        let _our_safe_to_close = phone_read_old(&mut peer, &phone).await;
        phone_write_old(&mut peer, &phone, &for_bwu_safe_to_close()).await;
        let frame = consumer_read_bwu(&old_channel).await;
        bwu.handle.incoming_frame(frame, ep, Medium::BleL2cap).await;
        drop(peer);

        // Convergence: a (ep, WifiHotspot) bandwidth change is recorded.
        let mut converged = false;
        for _ in 0..300 {
            if !bwu.handle.is_upgrade_ongoing(ep).await {
                converged = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(converged, "the WIFI_HOTSPOT upgrade should converge");
        assert!(
            bwu.handle
                .bandwidth_changed_events()
                .await
                .iter()
                .any(|(id, m)| id == ep && *m == Medium::WifiHotspot),
            "a (PEER, WifiHotspot) bandwidth change should be recorded"
        );

        // The upgraded channel is a WIFI_HOTSPOT channel, distinct from the old one.
        let upgraded = bwu
            .handle
            .get_upgraded_channel(ep)
            .await
            .expect("the upgraded channel is retrievable after convergence");
        assert_eq!(upgraded.medium(), Medium::WifiHotspot);
        assert_ne!(
            Arc::as_ptr(&old_channel) as *const (),
            Arc::as_ptr(&upgraded) as *const (),
            "the upgraded channel must be a different Arc than the old one"
        );

        // Seq continuity across the swap (out 3->4, in 2->3) — the same invariant
        // the WIFI_LAN test proves, exercised over the hotspot channel.
        assert_eq!(ours.server_seq(), 3, "outbound seq preserved across the swap");
        assert_eq!(ours.client_seq(), 2, "inbound seq preserved across the swap");

        let phone_new_chan = responder.join().unwrap();
        upgraded.enable_encryption(ours.clone());
        phone_new_chan.enable_encryption(phone.clone());

        let payload = b"first payload after the hotspot upgrade".to_vec();
        let wrote = {
            let up = upgraded.clone();
            let p = payload.clone();
            tokio::task::spawn_blocking(move || up.write(&p))
                .await
                .unwrap()
        };
        assert_eq!(wrote, Exception::Success);
        assert_eq!(ours.server_seq(), 4, "outbound seq continues (3 -> 4)");
        let phone_got = {
            let c = phone_new_chan.clone();
            tokio::task::spawn_blocking(move || c.read())
                .await
                .unwrap()
                .expect("phone decrypts our frame at the continued inbound seq (4)")
        };
        assert_eq!(phone_got, payload);

        let reply = b"ack from the phone over the hotspot".to_vec();
        {
            let c = phone_new_chan.clone();
            let r = reply.clone();
            tokio::task::spawn_blocking(move || c.write(&r))
                .await
                .unwrap();
        }
        let our_got = {
            let up = upgraded.clone();
            tokio::task::spawn_blocking(move || up.read())
                .await
                .unwrap()
                .expect("we decrypt the phone's frame at the continued inbound seq (3)")
        };
        assert_eq!(our_got, reply);
        assert_eq!(ours.client_seq(), 3, "inbound seq continues (2 -> 3)");
    }
}
