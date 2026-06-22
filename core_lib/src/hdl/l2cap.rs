// Quick Share BLE transport — L2CAP CoC server.
//
// A modern Quick Share sender reads our advertisement header (PSM), opens an
// L2CAP CoC to that PSM, fetches the advertisement, opens a data connection, then
// runs the normal Quick Share protocol. All packets are length-prefixed with a
// 4-byte big-endian outer length (google/nearby ble_l2cap_packet + ble_socket):
//   phone -> us: REQUEST_ADVERTISEMENT (1) [advert-hash]
//   us -> phone: RESPONSE_ADVERTISEMENT (21) [inner BleAdvertisement]
//   phone -> us: REQUEST_DATA_CONNECTION (3)
//   us -> phone: RESPONSE_DATA_CONNECTION_READY (23)
//   ... then the OfflineFrame stream (CONNECTION_REQUEST, UKEY2, consent, files).
//
// On the data connection each OfflineFrame is wrapped as
//   [4B outer len][3B service_id_hash fc9f5e][4B inner len][OfflineFrame]
// We bridge that wrapper to/from the plain [4B len][OfflineFrame] framing that
// InboundRequest (the existing TCP receiver state machine) speaks, via an
// in-memory duplex pipe, and reuse InboundRequest for the whole transfer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bluer::l2cap::{SocketAddr, Stream, StreamListener};
use bluer::{Address, AddressType};
use nearby_rs::bwu::EndpointChannel;
use nearby_rs::mediums::Medium;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::channel::ChannelMessage;

use super::bwu_channel::EndpointChannelBridge;
use super::{InboundRequest, State, Transport};

const INNER_NAME: &str = "L2capServer";

// Fixed LE PSM (dynamic LE range is 0x80..=0xFF).
pub const L2CAP_PSM: u16 = 0x0083;

// BleL2capPacket command bytes (google/nearby ble_l2cap_packet.cc).
const CMD_REQUEST_ADVERTISEMENT: u8 = 1;
const CMD_REQUEST_ADVERTISEMENT_FINISH: u8 = 2;
const CMD_REQUEST_DATA_CONNECTION: u8 = 3;
const CMD_RESPONSE_ADVERTISEMENT: u8 = 21;
const CMD_RESPONSE_DATA_CONNECTION_READY: u8 = 23;

// First 3 bytes of SHA-256("NearbySharing"): the Quick Share service id hash,
// which prefixes each OfflineFrame on the BLE data connection.
const SERVICE_ID_HASH: [u8; 3] = [0xfc, 0x9f, 0x5e];

const MAX_PACKET: usize = 256 * 1024;

pub struct L2capServer {
    psm: u16,
    inner: Vec<u8>,
    sender: Sender<ChannelMessage>,
}

impl L2capServer {
    pub fn new(psm: u16, inner: Vec<u8>, sender: Sender<ChannelMessage>) -> Self {
        Self { psm, inner, sender }
    }

    pub async fn run(self, ctk: CancellationToken, tracker: TaskTracker) -> Result<(), anyhow::Error> {
        let sa = SocketAddr::new(Address::any(), AddressType::LePublic, self.psm);
        let listener = StreamListener::bind(sa).await?;
        info!("{INNER_NAME}: listening on LE L2CAP PSM {:#06x}", self.psm);

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: cancelled, stopping");
                    break;
                }
                r = listener.accept() => {
                    match r {
                        Ok((stream, peer)) => {
                            info!("{INNER_NAME}: L2CAP connection from {peer:?}");
                            let inner = self.inner.clone();
                            let sender = self.sender.clone();
                            let id = peer.addr.to_string();
                            // Hand the per-connection task the cancellation token so a
                            // graceful shutdown (RQS::stop) tears down an in-flight
                            // WIFI_HOTSPOT SoftAP instead of leaking it, and spawn it
                            // ON THE TRACKER so RQS::stop()'s tracker.wait() awaits that
                            // teardown before the runtime is dropped.
                            let conn_ctk = ctk.clone();
                            tracker.spawn(async move {
                                if let Err(e) = handle(stream, inner, sender, id, conn_ctk).await {
                                    debug!("{INNER_NAME}: connection ended: {e}");
                                }
                            });
                        }
                        Err(e) => error!("{INNER_NAME}: accept error: {e}"),
                    }
                }
            }
        }

        Ok(())
    }
}

async fn read_packet<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad frame length {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

// QS_BWU_ACTOR: a dedicated blocking thread that drains a StreamChannel (deframe +
// decrypt once its cipher is installed) into an mpsc the async receive loop selects,
// so a frame is never lost to select cancellation. Exits when the channel closes or
// the receiver is dropped.
fn spawn_channel_reader(channel: Arc<dyn EndpointChannel>, tx: mpsc::Sender<Vec<u8>>) {
    std::thread::spawn(move || loop {
        match channel.read() {
            Ok(bytes) => {
                if tx.blocking_send(bytes).is_err() {
                    break;
                }
            }
            Err(_) => break, // channel closed / transport gone
        }
    });
}

// A plaintext KEEP_ALIVE OfflineFrame (no BLE wrapping — t_out adds the [4B outer]
// [3B service-id hash] toward L2CAP, and the StreamChannel adds the [4B len]). Used
// on the cipher-disabled OLD channel to un-park the phone's prior-channel read after
// the medium switch, landing plaintext like the proven t_out nudge.
fn plain_keepalive() -> Vec<u8> {
    use crate::location_nearby_connections as lnc;
    use prost::Message;
    lnc::OfflineFrame {
        version: Some(lnc::offline_frame::Version::V1.into()),
        v1: Some(lnc::V1Frame {
            r#type: Some(lnc::v1_frame::FrameType::KeepAlive.into()),
            keep_alive: Some(lnc::KeepAliveFrame { ack: Some(false) }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

async fn handle(
    mut stream: Stream,
    inner: Vec<u8>,
    sender: Sender<ChannelMessage>,
    id: String,
    ctk: CancellationToken,
) -> Result<(), anyhow::Error> {
    // Phase 1: BleL2capPacket handshake — answer advert fetches and the data
    // connection request. Returns once the data connection is ready.
    loop {
        let pkt = read_packet(&mut stream).await?;
        match pkt[0] {
            CMD_REQUEST_ADVERTISEMENT => {
                let mut resp = Vec::with_capacity(3 + inner.len());
                resp.push(CMD_RESPONSE_ADVERTISEMENT);
                resp.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                resp.extend_from_slice(&inner);
                write_frame(&mut stream, &resp).await?;
            }
            CMD_REQUEST_ADVERTISEMENT_FINISH => {
                debug!("{INNER_NAME}: advertisement fetch finished");
            }
            CMD_REQUEST_DATA_CONNECTION => {
                write_frame(&mut stream, &[CMD_RESPONSE_DATA_CONNECTION_READY]).await?;
                info!("{INNER_NAME}: data connection ready; entering protocol");
                break;
            }
            other => debug!("{INNER_NAME}: unexpected L2CAP command {other:#04x}"),
        }
    }

    // Phase 2: bridge the BLE OfflineFrame wrapper <-> the plain [4B len][frame]
    // framing InboundRequest speaks, then run the existing receiver protocol.
    let (proto, bridge) = tokio::io::duplex(MAX_PACKET);
    let (mut l2_rd, mut l2_wr) = tokio::io::split(stream);
    let (mut br_rd, mut br_wr) = tokio::io::split(bridge);

    // Set by the driver once a WiFi upgrade succeeds. t_out reads it after its
    // relay loop ends to decide whether to run the prior-channel keepalive nudge.
    let upgraded_flag = Arc::new(AtomicBool::new(false));
    let upgraded_out = upgraded_flag.clone();
    let keepalive_frame = wrapped_keepalive();

    // L2CAP -> protocol: strip [3B service_id_hash] from each wrapped frame.
    let t_in = tokio::spawn(async move {
        loop {
            let body = match read_packet(&mut l2_rd).await {
                Ok(b) => b,
                Err(e) => {
                    debug!("{INNER_NAME}: l2cap read ended: {e}");
                    break;
                }
            };
            if body.len() > 3 && body[..3] == SERVICE_ID_HASH {
                // body = [3B hash][4B inner len][frame]; forward [4B inner len][frame].
                if br_wr.write_all(&body[3..]).await.is_err() {
                    break;
                }
            } else {
                // BLE-socket control frame (not an OfflineFrame) — safe to skip.
                trace!("{INNER_NAME}: skipping non-frame packet ({} bytes)", body.len());
            }
        }
    });

    // protocol -> L2CAP: wrap each [4B len][frame] as [4B outer][3B hash][4B len][frame].
    let t_out = tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 4];
            if br_rd.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_PACKET {
                break;
            }
            let mut frame = vec![0u8; len];
            if br_rd.read_exact(&mut frame).await.is_err() {
                break;
            }
            // blob = the original [4B len][frame]; outer = 3 + blob.len().
            let blob_len = 4 + len;
            let outer = (3 + blob_len) as u32;
            let mut out = Vec::with_capacity(4 + outer as usize);
            out.extend_from_slice(&outer.to_be_bytes());
            out.extend_from_slice(&SERVICE_ID_HASH);
            out.extend_from_slice(&len_buf);
            out.extend_from_slice(&frame);
            if l2_wr.write_all(&out).await.is_err() || l2_wr.flush().await.is_err() {
                break;
            }
        }

        // The relay loop only ends when `proto` is dropped. On a WiFi upgrade that
        // happens at set_socket(), right after SAFE_TO_CLOSE was flushed above.
        // The phone then parks its prior-channel Read() (bwu ProcessSafeToClose)
        // and won't unpause/stream the payload until that read returns — and a
        // bare close doesn't wake it promptly over BLE L2CAP (~10s timeout), but
        // DATA does. Feed plaintext KEEP_ALIVEs on the old channel so the read
        // returns; the phone then Close()s this channel (failing our next write,
        // ending the loop) and Resume()s WiFi. We wait first so the phone has
        // received SAFE_TO_CLOSE and DisableEncryption()'d the old channel (these
        // are read as plaintext). The 250ms also closes the race with the driver
        // setting `upgraded_flag` right after set_socket(). Plaintext => no d2d
        // sequence impact, and harmless if the phone's read loop reads it instead.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if upgraded_out.load(Ordering::Relaxed) {
            debug!("{INNER_NAME}: nudging phone's prior-channel read with keepalives");
            let mut sent = 0;
            for _ in 0..25 {
                if l2_wr.write_all(&keepalive_frame).await.is_err() || l2_wr.flush().await.is_err()
                {
                    break; // phone closed the old channel — it switched, we're done
                }
                sent += 1;
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            debug!("{INNER_NAME}: keepalive nudge ended after {sent} frame(s)");
        }
    });

    // QS_BWU_ACTOR (experimental): route the receive path through nearby-rs's
    // StreamChannel (an EndpointChannelBridge over `proto`) so framing + d2d crypto
    // + the sequence counters live in the shared channel — the foundation for
    // driving the WiFi upgrade through the BwuActor. Unset = the proven inline path
    // (Pixel-validated). Inc 1 routes the DATA path only (no WiFi offer); the actor
    // + upgrade routing are Inc 2. See .bwu-integration-design.md.
    let use_actor = std::env::var("QS_BWU_ACTOR").is_ok();
    if use_actor {
        warn!("{INNER_NAME}: QS_BWU_ACTOR set — routing the WiFi upgrade through the BwuActor (Inc 2)");
        let ep = "PHONE"; // a stable key for the actor's endpoint maps
        let lan = lan_ipv4();

        // The channel owns `proto`; t_in/t_out still bridge L2CAP <-> `proto` with
        // the channel pumps on the `proto` end. A dedicated blocking reader drains
        // the channel (deframe + decrypt) into an mpsc the loop selects.
        let ecb = EndpointChannelBridge::new_plaintext(proto, "beamish", Medium::BleL2cap);
        let channel: Arc<dyn EndpointChannel> = ecb.channel.clone();
        let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(64);
        spawn_channel_reader(channel.clone(), frame_tx);

        // Phase 4 offer policy: prefer a WIFI_HOTSPOT upgrade — the phone joins a
        // SoftAP we stand up, which is immune to its infra-WiFi (STA) flap that makes
        // the WIFI_LAN slow-start — when QS_BWU_HOTSPOT is set and the linux-softap
        // build can bring an AP up; otherwise WIFI_LAN. `NmSoftAp::new()` returns
        // None when there's no connected STA to co-channel against, so we cleanly
        // fall back to WIFI_LAN.
        #[cfg(all(feature = "linux-softap", target_os = "linux"))]
        let softap: Option<Arc<dyn nearby_rs::bwu::SoftAp>> =
            if std::env::var("QS_BWU_HOTSPOT").is_ok() {
                super::nm_softap::NmSoftAp::new()
                    .map(|s| Arc::new(s) as Arc<dyn nearby_rs::bwu::SoftAp>)
            } else {
                None
            };
        #[cfg(not(all(feature = "linux-softap", target_os = "linux")))]
        let softap: Option<Arc<dyn nearby_rs::bwu::SoftAp>> = None;

        let primary_medium = if softap.is_some() {
            Medium::WifiHotspot
        } else {
            Medium::WifiLan
        };

        // Pre-warm: stand the SoftAP up NOW, off-thread, so its (variable, up to a
        // few-second) bring-up overlaps the BLE/UKEY2 handshake. NmSoftAp::start is
        // idempotent + cached on the shared Arc, so when the handler later calls it
        // (during initiate_bwu) it returns the cached creds instantly and the
        // WIFI_HOTSPOT offer goes out with no AP-bring-up latency on the critical
        // path. The handler's revert/our shutdown() tears down this same cached AP.
        if let Some(sa) = softap.clone() {
            tokio::task::spawn_blocking(move || {
                if sa.start("beamish").is_some() {
                    info!("{INNER_NAME}: BWU(actor) pre-warmed the SoftAP (overlapping the handshake)");
                }
            });
        }

        // The BwuActor + its medium handlers: the WIFI_LAN handler binds 0.0.0.0 and
        // advertises the LAN IP the phone dials; the (optional) WIFI_HOTSPOT handler
        // derives its bind/gateway from the SoftAP. The actor offers
        // UPGRADE_PATH_AVAILABLE, runs the new-channel handshake, and swaps the
        // registered channel on convergence.
        let bwu = super::bwu_channel::BwuSession::spawn(
            ep,
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv4Addr::from(lan),
            softap,
        );

        // InboundRequest reads via the channel reader and writes via the channel, so
        // its own socket is inert — give it a throwaway duplex half.
        let (dummy, _dummy_peer) = tokio::io::duplex(8);
        let mut ir = InboundRequest::new(Transport::Duplex(dummy), id, sender);
        ir.set_channel(channel.clone());
        ir.set_bwu(bwu.handle.clone(), ep);

        let mut offered = false;
        let mut upgraded = false;
        // The medium currently offered. Starts at the primary (WIFI_HOTSPOT when a
        // SoftAP is available, else WIFI_LAN); a stuck hotspot upgrade falls back to
        // WIFI_LAN — the hotspot-primary / WIFI_LAN-fallback policy.
        let mut offer_medium = primary_medium;
        let mut reoffers = 0u32;
        // Re-offer count after which a stuck WIFI_HOTSPOT upgrade gives up on the AP
        // and falls back to the (slower but always-reachable) WIFI_LAN path.
        const HOTSPOT_FALLBACK_AFTER: u32 = 3;
        loop {
            // Once the NC connection is accepted (and the channel cipher is on), drive
            // the actor to OFFER the upgrade on the channel — replaces the inline
            // offer_wifi_upgrade. FIFO command ordering means a subsequent
            // is_upgrade_ongoing/get_upgraded_channel sees the in-progress upgrade.
            if !offered && !upgraded && ir.state.state == State::SentConnectionResponse {
                offered = true;
                bwu.handle.connection_initiated(ep, false, false).await;
                bwu.handle.connection_accepted(ep).await;
                bwu.handle.register_channel(ep, channel.clone()).await;
                bwu.handle.initiate_bwu(ep, offer_medium).await;
                info!("{INNER_NAME}: BWU(actor) offered {offer_medium:?} (lan {lan:?}); awaiting handshake");
            } else if offered && !upgraded && ir.wifi_retry_requested {
                // The phone signalled BANDWIDTH_UPGRADE_RETRY (its WiFi recovered, or
                // it bounced off our offer).
                ir.wifi_retry_requested = false;
                reoffers += 1;
                if offer_medium == Medium::WifiHotspot && reoffers >= HOTSPOT_FALLBACK_AFTER {
                    offer_medium = Medium::WifiLan;
                    warn!("{INNER_NAME}: BWU(actor) WIFI_HOTSPOT stuck after {reoffers} tries; falling back to WIFI_LAN");
                }
                // Clear any in-progress upgrade WITHOUT reverting the handler first:
                // the phone may retry without having sent an UPGRADE_FAILURE (which is
                // what otherwise clears the actor's in-progress guard), so a bare
                // re-initiate would be silently dropped. reset_upgrade unblocks the
                // re-offer while reusing the standing medium (the pre-warmed SoftAP),
                // so there's no AP churn. (#23)
                bwu.handle.reset_upgrade(ep).await;
                info!("{INNER_NAME}: BWU(actor) re-offering {offer_medium:?} (retry #{reoffers})");
                bwu.handle.initiate_bwu(ep, offer_medium).await;
            }

            // Hybrid teardown: the phone's LAST_WRITE means the actor registered the
            // NEW channel and is sending SAFE_TO_CLOSE; the Pixel then parks its OLD
            // read (it never sends its own SAFE_TO_CLOSE, so the actor's
            // process_safe_to_close would stall). Don't wait for it — un-park the
            // phone and switch to WiFi ourselves.
            if offered && !upgraded && ir.bwu_last_write_seen {
                ir.bwu_last_write_seen = false;
                // run_upgrade_protocol (registers the NEW channel) runs on the actor
                // task and may not be done when the phone's LAST_WRITE reached us —
                // poll briefly for the upgraded WiFi channel (WIFI_LAN or WIFI_HOTSPOT).
                let mut new_chan = None;
                for _ in 0..30 {
                    match bwu.handle.get_upgraded_channel(ep).await {
                        Some(c) if matches!(c.medium(), Medium::WifiLan | Medium::WifiHotspot) => {
                            new_chan = Some(c);
                            break;
                        }
                        _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                    }
                }
                if let Some(new_chan) = new_chan {
                    upgraded = true;
                    // Un-park the phone: it parked its OLD read after our SAFE_TO_CLOSE.
                    // The OLD channel is abandoned now, so disable its cipher and feed
                    // plaintext KEEP_ALIVEs (the phone DisableEncryption'd its OLD side
                    // too); t_out wraps them into BLE framing toward L2CAP. The delay
                    // lets the actor's SAFE_TO_CLOSE reach the phone first.
                    let nudge = channel.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        nudge.disable_encryption();
                        let ka = plain_keepalive();
                        for _ in 0..25 {
                            if nudge.write(&ka) != nearby_rs::frames::Exception::Success {
                                break; // phone closed OLD — it switched to WiFi
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        }
                    });
                    // Continue the transfer on the NEW (WiFi) channel: resume it (the
                    // upgrade protocol paused it), install the shared session so the d2d
                    // sequence continues, then read it via a fresh blocking reader.
                    let new_medium = new_chan.medium();
                    new_chan.resume();
                    if let Some(session) = ir.session() {
                        new_chan.enable_encryption(session);
                    }
                    let (ntx, nrx) = mpsc::channel::<Vec<u8>>(64);
                    spawn_channel_reader(new_chan.clone(), ntx);
                    frame_rx = nrx;
                    ir.set_channel(new_chan);
                    info!("{INNER_NAME}: BWU(actor) handoff to {new_medium:?} (nudging the prior channel)");
                    continue;
                }
                warn!("{INNER_NAME}: BWU(actor) saw LAST_WRITE but no WiFi channel; staying on L2CAP");
            }

            // Drive one frame/command. While an upgrade is offered but not yet handed
            // off, bound the wait so a failed un-park can't hang the loop forever. The
            // WIFI_HOTSPOT join (the phone leaves its infra WiFi, joins our AP, gets
            // DHCP, then dials) measured ~9s in the spike and can exceed WIFI_LAN's
            // 15s ceiling on a retry, so give the hotspot path a larger budget.
            let step = ir.handle_via_channel(&mut frame_rx);
            // A graceful shutdown (RQS::stop cancels the token) must break out of the
            // loop so the post-loop `bwu.handle.shutdown()` tears down any in-flight
            // SoftAP rather than leaking it past process exit.
            let r = if offered && !upgraded {
                let secs = if offer_medium == Medium::WifiHotspot {
                    30
                } else {
                    15
                };
                tokio::select! {
                    _ = ctk.cancelled() => {
                        info!("{INNER_NAME}: BWU(actor) cancelled mid-upgrade; tearing down");
                        break;
                    }
                    r = tokio::time::timeout(std::time::Duration::from_secs(secs), step) => match r {
                        Ok(r) => r,
                        Err(_) => {
                            warn!("{INNER_NAME}: BWU(actor) upgrade stalled {secs}s; ending transfer");
                            break;
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = ctk.cancelled() => {
                        info!("{INNER_NAME}: BWU(actor) cancelled; tearing down");
                        break;
                    }
                    r = step => r,
                }
            };
            match r {
                Ok(()) => {}
                Err(e) => {
                    if !matches!(
                        e.downcast_ref::<crate::errors::AppError>(),
                        Some(crate::errors::AppError::NotAnError)
                    ) {
                        debug!("{INNER_NAME}: protocol ended: {e} (state {:?})", ir.state.state);
                    }
                    break;
                }
            }
        }

        // Deterministic teardown: Shutdown reverts every handler synchronously on the
        // live actor task (WIFI_HOTSPOT → SoftAp::stop tears the AP down), so the
        // SoftAP never outlives the transfer waiting on the async actor-abort/Drop
        // chain. Bounded so a wedged teardown can't hang the connection task.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(25), bwu.handle.shutdown()).await;
        drop(ecb); // keep the channel pumps alive until the loop ends
        drop(bwu);
        t_in.abort();
        t_out.abort();
        return Ok(());
    }

    // Run the existing receiver state machine over the bridged stream.
    let mut ir = InboundRequest::new(Transport::Duplex(proto), id, sender);
    // NOTE: we used to defer the first sharing frame (PairedKeyEncryption) until
    // after the upgrade to keep the d2d sequence in lockstep. That's now handled
    // by the channel drain (drain_prior_channel), and deferring actively breaks the
    // sharing handshake ORDER (it sent our PairedKeyEncryption after our
    // PairedKeyResult), so the phone stalled and disconnected. We no longer defer.

    // WiFi bandwidth-upgrade state. After the NC connection is accepted we offer a
    // WIFI_LAN upgrade and bind an ephemeral TCP listener, then race:
    //   * the phone connects over TCP        -> swap transport to WiFi (fast path)
    //   * the phone sends UPGRADE_FAILURE     -> fall back to L2CAP immediately
    //   * neither within 12s (phone silent)   -> abort the connection
    // Reacting to UPGRADE_FAILURE the moment it arrives (instead of blocking on
    // accept()) keeps the L2CAP fallback in sequence and lets the consent dialog
    // appear without a multi-second stall.
    let mut wifi_listener: Option<tokio::net::TcpListener> = None;
    let mut offered = false; // initial offer made
    let mut upgraded = false; // successfully switched to WiFi
    // The phone's infra WiFi (STA) briefly drops during BLE/Nearby setup and
    // recovers ~2s later; offering WIFI_LAN in that gap yields UPGRADE_FAILURE
    // (WITHOUT_CONNECTED_WIFI_NETWORK). We re-offer whenever the phone signals its
    // WiFi is back via BANDWIDTH_UPGRADE_RETRY. QS_UPGRADE_DELAY_MS optionally
    // delays the INITIAL offer past the flap.
    let upgrade_delay_ms: u64 = std::env::var("QS_UPGRADE_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut delayed = false;
    loop {
        // (Re-)offer the WIFI_LAN upgrade: once on reaching SentConnectionResponse,
        // and again whenever the phone asks (BANDWIDTH_UPGRADE_RETRY = WiFi back).
        let do_initial = !offered && ir.state.state == State::SentConnectionResponse;
        let do_retry = ir.wifi_retry_requested;
        if !upgraded && wifi_listener.is_none() && (do_initial || do_retry) {
            if do_retry {
                ir.wifi_retry_requested = false;
                info!("{INNER_NAME}: phone signalled WiFi ready; re-offering WIFI_LAN");
            } else if !delayed && upgrade_delay_ms > 0 {
                delayed = true;
                info!("{INNER_NAME}: delaying WiFi offer {upgrade_delay_ms}ms to clear the STA flap");
                tokio::time::sleep(std::time::Duration::from_millis(upgrade_delay_ms)).await;
            }
            offered = true;
            match offer_wifi_upgrade(&mut ir).await {
                Ok(l) => wifi_listener = Some(l),
                Err(e) => warn!("{INNER_NAME}: couldn't offer WiFi upgrade ({e}); staying on L2CAP"),
            }
        }

        // While an upgrade offer is outstanding, race accept vs. L2CAP frames.
        if let Some(listener) = wifi_listener.take() {
            tokio::select! {
                r = listener.accept() => {
                    match r {
                        Ok((tcp, peer)) => {
                            info!("{INNER_NAME}: WiFi TCP connection from {peer}");
                            // Drain the old channel and switch atomically so the d2d
                            // sequence stays in lockstep (no "6 vs 5" race).
                            match handover_to_wifi(&mut ir, tcp).await {
                                Ok(()) => {
                                    info!("{INNER_NAME}: transport upgraded to WiFi-LAN");
                                    upgraded = true;
                                    // Don't abort the relay here. set_socket() in the handover
                                    // dropped the old `proto`, so t_out has drained+flushed
                                    // SAFE_TO_CLOSE and will now nudge the phone's parked
                                    // prior-channel read with plaintext KEEP_ALIVEs (see the
                                    // t_out keepalive phase) so it unpauses WiFi without the
                                    // ~10s stall. Both halves self-terminate once the phone
                                    // closes the old channel. This flag gates that phase.
                                    upgraded_flag.store(true, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    warn!("{INNER_NAME}: WiFi handover failed ({e}); staying on L2CAP");
                                    fallback_to_l2cap(&mut ir).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("{INNER_NAME}: WiFi accept failed ({e}); falling back to L2CAP");
                            fallback_to_l2cap(&mut ir).await;
                        }
                    }
                }
                r = ir.handle() => {
                    if let Err(e) = r {
                        match e.downcast_ref::<crate::errors::AppError>() {
                            Some(crate::errors::AppError::NotAnError) => {}
                            _ => debug!("{INNER_NAME}: protocol ended: {e} (state {:?})", ir.state.state),
                        }
                        break;
                    }
                    if ir.upgrade_rejected {
                        ir.upgrade_rejected = false;
                        info!("{INNER_NAME}: phone declined WiFi upgrade; staying on L2CAP, awaiting retry");
                        fallback_to_l2cap(&mut ir).await;
                        // Drop the listener; a BANDWIDTH_UPGRADE_RETRY re-offers.
                    } else {
                        // Unrelated frame (e.g. keepalive) — keep waiting for the
                        // accept/UPGRADE_FAILURE without disturbing the L2CAP read.
                        wifi_listener = Some(listener);
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(12)) => {
                    warn!("{INNER_NAME}: no WiFi connect/reply in 12s; staying on L2CAP, awaiting retry");
                    fallback_to_l2cap(&mut ir).await;
                    // Drop the listener; continue on L2CAP (a retry can re-offer).
                }
            }
            continue;
        }

        match ir.handle().await {
            Ok(()) => {}
            Err(e) => {
                match e.downcast_ref::<crate::errors::AppError>() {
                    Some(crate::errors::AppError::NotAnError) => {}
                    _ => debug!("{INNER_NAME}: protocol ended: {e} (state {:?})", ir.state.state),
                }
                break;
            }
        }
    }

    t_in.abort();
    t_out.abort();
    Ok(())
}

// Offer a WIFI_LAN bandwidth upgrade and bind the ephemeral TCP listener the phone
// should connect to. Returns the listener so the caller can race accept() against
// the phone's UPGRADE_FAILURE and fall back to L2CAP without delay.
async fn offer_wifi_upgrade(
    ir: &mut InboundRequest<Transport>,
) -> Result<tokio::net::TcpListener, anyhow::Error> {
    let ip = lan_ipv4();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
    let port = listener.local_addr()?.port();
    ir.send_wifi_upgrade(ip, port).await?;
    info!(
        "{INNER_NAME}: BWU offered {}.{}.{}.{}:{port}; awaiting WiFi connection",
        ip[0], ip[1], ip[2], ip[3]
    );
    Ok(listener)
}

// Send the deferred sharing frame on the existing L2CAP channel so the transfer
// continues over Bluetooth when the WiFi upgrade doesn't happen.
async fn fallback_to_l2cap(ir: &mut InboundRequest<Transport>) {
    if let Err(e) = ir.abort_wifi_upgrade().await {
        debug!("{INNER_NAME}: L2CAP fallback send failed: {e}");
    }
}

// Complete the WiFi bandwidth upgrade with a proper channel-drain handshake so the
// d2d sequence stays in lockstep across the medium switch:
//   1. ACK the phone's plaintext CLIENT_INTRODUCTION on the new WiFi socket — this
//      unblocks it to send LAST_WRITE_TO_PRIOR_CHANNEL on the old L2CAP channel.
//   2. Drain the old L2CAP channel (counting every inbound d2d frame) until that
//      LAST_WRITE arrives.
//   3. Swap the transport to WiFi and send the deferred sharing frame.
async fn handover_to_wifi(
    ir: &mut InboundRequest<Transport>,
    mut tcp: tokio::net::TcpStream,
) -> Result<(), anyhow::Error> {
    wifi_introduction_ack(&mut tcp).await?;
    ir.drain_prior_channel().await?;
    // Acknowledge the drain on the OLD channel before abandoning it.
    ir.send_safe_to_close().await?;
    ir.set_socket(Transport::Tcp(tcp));
    ir.send_deferred_after_upgrade().await?;
    Ok(())
}

// Read the phone's plaintext CLIENT_INTRODUCTION off the new WiFi socket and reply
// with a plaintext CLIENT_INTRODUCTION_ACK. Both are [4B BE len][OfflineFrame] and
// are NOT part of the encrypted d2d sequence.
async fn wifi_introduction_ack(tcp: &mut tokio::net::TcpStream) -> Result<(), anyhow::Error> {
    use crate::location_nearby_connections as lnc;
    use lnc::bandwidth_upgrade_negotiation_frame as bwu;
    use prost::Message;

    let mut len_buf = [0u8; 4];
    tcp.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(anyhow::anyhow!("bad introduction length {len}"));
    }
    let mut buf = vec![0u8; len];
    tcp.read_exact(&mut buf).await?;
    debug!("{INNER_NAME}: read CLIENT_INTRODUCTION on WiFi ({len} bytes); sending ACK");

    let ack = lnc::OfflineFrame {
        version: Some(lnc::offline_frame::Version::V1.into()),
        v1: Some(lnc::V1Frame {
            r#type: Some(lnc::v1_frame::FrameType::BandwidthUpgradeNegotiation.into()),
            bandwidth_upgrade_negotiation: Some(lnc::BandwidthUpgradeNegotiationFrame {
                event_type: Some(bwu::EventType::ClientIntroductionAck.into()),
                client_introduction_ack: Some(bwu::ClientIntroductionAck {}),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let bytes = ack.encode_to_vec();
    tcp.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    tcp.write_all(&bytes).await?;
    tcp.flush().await?;
    Ok(())
}

// Build a PLAINTEXT KEEP_ALIVE OfflineFrame already wrapped in the BLE data-
// connection framing ([4B outer][3B service_id_hash][4B inner len][frame]) so the
// relay can write it straight to the L2CAP socket. Used to nudge the phone's
// parked prior-channel read after a WiFi upgrade (see the t_out keepalive phase).
fn wrapped_keepalive() -> Vec<u8> {
    use crate::location_nearby_connections as lnc;
    use prost::Message;

    let frame = lnc::OfflineFrame {
        version: Some(lnc::offline_frame::Version::V1.into()),
        v1: Some(lnc::V1Frame {
            r#type: Some(lnc::v1_frame::FrameType::KeepAlive.into()),
            keep_alive: Some(lnc::KeepAliveFrame { ack: Some(false) }),
            ..Default::default()
        }),
    };
    let inner = frame.encode_to_vec();
    let len = inner.len();
    let outer = (3 + 4 + len) as u32;
    let mut out = Vec::with_capacity(4 + outer as usize);
    out.extend_from_slice(&outer.to_be_bytes());
    out.extend_from_slice(&SERVICE_ID_HASH);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

fn lan_ipv4() -> [u8; 4] {
    use std::net::{IpAddr, UdpSocket};
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let IpAddr::V4(ip) = local.ip() {
                    return ip.octets();
                }
            }
        }
    }
    [0, 0, 0, 0]
}
