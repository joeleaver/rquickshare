use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::Duration;

use nearby_rs::bwu::{BwuHandle, EndpointChannel};
use nearby_rs::frames::Exception;
use nearby_rs::mediums::Medium as NbMedium;

use anyhow::anyhow;
use bytes::Bytes;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::broadcast::{Receiver, Sender};

use super::{InnerState, State, UkeySession};
use crate::channel::{ChannelAction, ChannelDirection, ChannelMessage};
use crate::hdl::info::{InternalFileInfo, TransferMetadata};
use crate::hdl::{TextPayloadInfo, TextPayloadType};
use crate::location_nearby_connections::payload_transfer_frame::{
    payload_header, PacketType, PayloadChunk, PayloadHeader,
};
use crate::location_nearby_connections::{KeepAliveFrame, OfflineFrame, PayloadTransferFrame};
use crate::securegcm::ukey2_alert::AlertType;
use crate::securegcm::{
    ukey2_message, Ukey2Alert, Ukey2ClientFinished, Ukey2ClientInit, Ukey2HandshakeCipher,
    Ukey2Message, Ukey2ServerInit,
};
use crate::securemessage::{
    EcP256PublicKey, GenericPublicKey, PublicKeyType, SecureMessage,
};
use crate::sharing_nearby::{paired_key_result_frame, text_metadata};
use crate::utils::{
    encode_point, gen_ecdsa_keypair, gen_random, get_download_dir, hkdf_extract_expand,
    stream_read_exact, to_four_digit_string, DeviceType, RemoteDeviceInfo,
};
use crate::{location_nearby_connections, sharing_nearby};

const SANE_FRAME_LENGTH: i32 = 5 * 1024 * 1024;
const SANITY_DURATION: Duration = Duration::from_micros(10);

/// Map a nearby-rs `StreamChannel` write `Exception` to our `Result`
/// (`Success` => `Ok`). Used on the `QS_BWU_ACTOR` write path.
fn exception_to_result(ex: Exception) -> Result<(), anyhow::Error> {
    if ex == Exception::Success {
        Ok(())
    } else {
        Err(anyhow!("StreamChannel write failed: {ex:?}"))
    }
}

#[derive(Debug)]
/// A swappable transport so a connection bootstrapped over BLE L2CAP (the duplex
/// bridge) can be upgraded to WiFi-LAN (TCP) mid-session without disturbing the
/// InboundRequest's UKEY2 / sequence state.
pub enum Transport {
    Duplex(DuplexStream),
    Tcp(TcpStream),
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Duplex(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Duplex(s) => Pin::new(s).poll_write(cx, buf),
            Transport::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Duplex(s) => Pin::new(s).poll_flush(cx),
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Duplex(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct InboundRequest<S = TcpStream> {
    socket: S,
    // QS_BWU_ACTOR: when set, the nearby-rs `StreamChannel` (an `EndpointChannelBridge`
    // over the same transport) owns framing + d2d crypto + the sequence counters.
    // Reads come from it (fed in via `handle_via_channel`); writes route through it
    // (`encrypt_and_send`/`send_frame`); the post-decode dispatch runs via
    // `process_decoded_offline_frame`. None = the proven inline path. The shared
    // `state.session` is installed as the channel's cipher once UKEY2 completes, so
    // the channel is the single sequence authority (no double-advance).
    channel: Option<Arc<dyn EndpointChannel>>,
    // QS_BWU_ACTOR (Inc 2): the BwuActor handle + the endpoint id used to key it.
    // When set, BandwidthUpgradeNegotiation frames read off the OLD channel are
    // forwarded to the actor (which drives the upgrade handshake) instead of the
    // inline `upgrade_rejected`/`prior_channel_drained`/`wifi_retry_requested` flags.
    bwu_handle: Option<BwuHandle>,
    bwu_ep: String,
    // Set when the phone's LAST_WRITE_TO_PRIOR_CHANNEL (its final OLD-channel frame)
    // is forwarded to the actor — the l2cap driver's cue to un-park the phone and
    // hand off to WiFi without waiting for the actor's process_safe_to_close (the
    // Pixel never sends SAFE_TO_CLOSE; it parks its OLD read instead).
    pub bwu_last_write_seen: bool,
    pub state: InnerState,
    sender: Sender<ChannelMessage>,
    receiver: Receiver<ChannelMessage>,
    // Set right after a WiFi bandwidth upgrade: the first frame on the new
    // channel is a PLAINTEXT CLIENT_INTRODUCTION (encryption resumes after).
    awaiting_introduction: bool,
    // When set, defer the first sharing frame until after the WiFi upgrade so the
    // sequence counters stay in lockstep across the medium switch.
    wifi_upgrade_pending: bool,
    // Set when the phone sends UPGRADE_FAILURE for our WiFi offer, so the driver
    // can fall back to L2CAP immediately instead of blocking on the dead accept().
    pub upgrade_rejected: bool,
    // Set when the phone sends LAST_WRITE_TO_PRIOR_CHANNEL on the old (L2CAP)
    // channel — its final frame there. The driver drains the old channel up to
    // this point before switching to WiFi so the d2d sequence stays in lockstep.
    pub prior_channel_drained: bool,
    // Set when the phone sends BANDWIDTH_UPGRADE_RETRY (its WiFi just recovered),
    // so the driver re-offers the WIFI_LAN upgrade.
    pub wifi_retry_requested: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> InboundRequest<S> {
    pub fn new(socket: S, id: String, sender: Sender<ChannelMessage>) -> Self {
        let receiver = sender.subscribe();

        Self {
            socket,
            channel: None,
            bwu_handle: None,
            bwu_ep: String::new(),
            bwu_last_write_seen: false,
            state: InnerState {
                id,
                server_seq: 0,
                client_seq: 0,
                state: State::Initial,
                encryption_done: true,
                ..Default::default()
            },
            sender,
            receiver,
            awaiting_introduction: false,
            wifi_upgrade_pending: false,
            upgrade_rejected: false,
            prior_channel_drained: false,
            wifi_retry_requested: false,
        }
    }

    /// Mark that this connection will be upgraded to WiFi, so the first sharing
    /// frame is deferred until after the medium switch (keeps sequences in sync).
    pub fn enable_wifi_upgrade(&mut self) {
        self.wifi_upgrade_pending = true;
    }

    /// Call right after swapping to the WiFi transport: the next frame will be a
    /// plaintext CLIENT_INTRODUCTION that we must ack before encryption resumes.
    pub fn expect_client_introduction(&mut self) {
        self.awaiting_introduction = true;
    }

    /// The WiFi upgrade didn't happen — fall back to the current (L2CAP) channel
    /// by sending the sharing frame we deferred, so the transfer can still run.
    pub async fn abort_wifi_upgrade(&mut self) -> Result<(), anyhow::Error> {
        if self.wifi_upgrade_pending {
            self.wifi_upgrade_pending = false;
            self.send_paired_key_encryption().await?;
        }
        Ok(())
    }

    /// After a successful WiFi upgrade, kick off the deferred sharing protocol on
    /// the new channel (no-op unless the deferral is enabled).
    pub async fn send_deferred_after_upgrade(&mut self) -> Result<(), anyhow::Error> {
        if self.wifi_upgrade_pending {
            self.wifi_upgrade_pending = false;
            self.send_paired_key_encryption().await?;
        }
        Ok(())
    }

    /// Reply to the phone's LAST_WRITE_TO_PRIOR_CHANNEL with SAFE_TO_CLOSE on the
    /// old (L2CAP) channel, per the BWU handshake, so the phone finalizes the
    /// medium switch. Encrypted (advances the d2d sequence) like LAST_WRITE.
    pub async fn send_safe_to_close(&mut self) -> Result<(), anyhow::Error> {
        use crate::location_nearby_connections as lnc;
        use lnc::bandwidth_upgrade_negotiation_frame as bwu;
        let frame = OfflineFrame {
            version: Some(lnc::offline_frame::Version::V1.into()),
            v1: Some(lnc::V1Frame {
                r#type: Some(lnc::v1_frame::FrameType::BandwidthUpgradeNegotiation.into()),
                bandwidth_upgrade_negotiation: Some(lnc::BandwidthUpgradeNegotiationFrame {
                    event_type: Some(bwu::EventType::SafeToClosePriorChannel.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        self.encrypt_and_send(&frame).await
    }

    /// Drain the old (L2CAP) channel after the WiFi socket connects: keep reading
    /// and processing its frames — advancing the inbound d2d sequence — until the
    /// phone sends LAST_WRITE_TO_PRIOR_CHANNEL (its final frame there). Without this
    /// we'd switch to WiFi mid-stream and miss that frame, desyncing the sequence
    /// (the "6 vs 5" error). Bounded so a phone that never sends LAST_WRITE can't
    /// hang the handover — we switch anyway after the timeout.
    pub async fn drain_prior_channel(&mut self) -> Result<(), anyhow::Error> {
        self.prior_channel_drained = false;
        while !self.prior_channel_drained {
            let mut length_buf = [0u8; 4];
            let read = stream_read_exact(&mut self.socket, &mut length_buf);
            match tokio::time::timeout(std::time::Duration::from_secs(3), read).await {
                Ok(r) => {
                    r?;
                    self._handle(length_buf).await?;
                }
                Err(_) => {
                    warn!("BWU: no LAST_WRITE_TO_PRIOR_CHANNEL within 3s; switching anyway");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Swap the underlying transport (used for the BLE L2CAP -> WiFi upgrade).
    /// The InnerState (UKEY2 keys, sequence counters) is preserved.
    pub fn set_socket(&mut self, socket: S) {
        self.socket = socket;
    }

    /// Send a BANDWIDTH_UPGRADE_NEGOTIATION / UPGRADE_PATH_AVAILABLE offering a
    /// WIFI_LAN socket, so the sender connects over TCP for the bulk transfer.
    pub async fn send_wifi_upgrade(&mut self, ip: [u8; 4], port: u16) -> Result<(), anyhow::Error> {
        // Validation hook: when QS_NEARBY_RS_FRAME is set, emit the
        // UPGRADE_PATH_AVAILABLE built by the nearby-rs port (golden-tested
        // against Google's `for_bwu_wifi_lan_path_available`) instead of our
        // hand-rolled one, to confirm the Pixel accepts it. Default = our frame.
        let frame = if std::env::var("QS_NEARBY_RS_FRAME").is_ok() {
            info!("BWU: building UPGRADE_PATH_AVAILABLE via nearby-rs (QS_NEARBY_RS_FRAME)");
            nearby_rs_wifi_upgrade_frame(ip, port)
        } else {
            beamish_wifi_upgrade_frame(ip, port)
        };
        info!("BWU: offering WIFI_LAN {}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3]);
        self.encrypt_and_send(&frame).await
    }

    /// Install the nearby-rs `StreamChannel` as the framing/crypto/sequence layer
    /// for the `QS_BWU_ACTOR` receive path. After this, drive the loop with
    /// [`handle_via_channel`](Self::handle_via_channel) (not [`handle`](Self::handle)),
    /// and route writes through the channel.
    pub fn set_channel(&mut self, channel: Arc<dyn EndpointChannel>) {
        self.channel = Some(channel);
    }

    /// QS_BWU_ACTOR (Inc 2): install the BwuActor handle + the endpoint id so
    /// BandwidthUpgradeNegotiation frames on the OLD channel are routed to the actor.
    pub fn set_bwu(&mut self, handle: BwuHandle, endpoint_id: impl Into<String>) {
        self.bwu_handle = Some(handle);
        self.bwu_ep = endpoint_id.into();
    }

    /// The shared UKEY2 d2d session, for installing as the upgraded channel's cipher
    /// after a successful bandwidth upgrade (keeps the sequence continuous).
    pub fn session(&self) -> Option<Arc<UkeySession>> {
        self.state.session.clone()
    }

    pub async fn handle(&mut self) -> Result<(), anyhow::Error> {
        // Buffer for the 4-byte length
        let mut length_buf = [0u8; 4];

        tokio::select! {
            i = self.receiver.recv() => self.handle_command(i).await,
            h = stream_read_exact(&mut self.socket, &mut length_buf) => {
                h?;
                self._handle(length_buf).await
            }
        }
    }

    /// `QS_BWU_ACTOR` receive driver: like [`handle`](Self::handle), but the next
    /// already-deframed (and, post-UKEY2, decrypted) frame comes from the
    /// `StreamChannel` reader over `frame_rx` instead of a socket read. App commands
    /// (accept/reject/cancel) are still serviced on the same select.
    pub async fn handle_via_channel(
        &mut self,
        frame_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), anyhow::Error> {
        tokio::select! {
            i = self.receiver.recv() => self.handle_command(i).await,
            f = frame_rx.recv() => match f {
                Some(bytes) => self.process_frame(bytes).await,
                // Channel reader closed (transport gone) — end the loop.
                None => Err(anyhow!(crate::errors::AppError::NotAnError)),
            }
        }
    }

    /// Service one inbound app command (accept/reject/cancel) from the broadcast
    /// receiver. Shared by [`handle`](Self::handle) and
    /// [`handle_via_channel`](Self::handle_via_channel).
    async fn handle_command(
        &mut self,
        i: Result<ChannelMessage, tokio::sync::broadcast::error::RecvError>,
    ) -> Result<(), anyhow::Error> {
        match i {
            Ok(channel_msg) => {
                if channel_msg.direction == ChannelDirection::LibToFront {
                    return Ok(());
                }

                if channel_msg.id != self.state.id {
                    return Ok(());
                }

                debug!("inbound: got: {:?}", channel_msg);
                match channel_msg.action {
                    Some(ChannelAction::AcceptTransfer) => {
                        self.accept_transfer().await?;
                    }
                    Some(ChannelAction::RejectTransfer) => {
                        self.update_state(
                            |e| {
                                e.state = State::Rejected;
                            },
                            true,
                        )
                        .await;

                        self.reject_transfer(Some(
                            sharing_nearby::connection_response_frame::Status::Reject,
                        ))
                        .await?;
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                    Some(ChannelAction::CancelTransfer) => {
                        self.update_state(
                            |e| {
                                e.state = State::Cancelled;
                            },
                            true,
                        )
                        .await;
                        self.disconnection().await?;
                        return Err(anyhow!(crate::errors::AppError::NotAnError));
                    }
                    None => {
                        trace!("inbound: nothing to do")
                    }
                }
            }
            Err(e) => {
                error!("inbound: channel error: {}", e);
            }
        }

        Ok(())
    }

    pub async fn _handle(&mut self, length_buf: [u8; 4]) -> Result<(), anyhow::Error> {
        let msg_length = u32::from_be_bytes(length_buf) as usize;
        // Ensure the message length is not unreasonably big to avoid allocation attacks
        if msg_length > SANE_FRAME_LENGTH as usize {
            error!("Message length too big");
            return Err(anyhow!("value"));
        }

        // Allocate buffer for the actual message and read it
        let mut frame_data = vec![0u8; msg_length];
        stream_read_exact(&mut self.socket, &mut frame_data).await?;

        self.process_frame(frame_data).await
    }

    /// Drive the state machine with one already-deframed payload. Separating this
    /// from the TCP read lets a non-TCP transport (BLE L2CAP) reuse the identical
    /// connection / UKEY2 / consent / transfer logic.
    pub async fn process_frame(&mut self, frame_data: Vec<u8>) -> Result<(), anyhow::Error> {
        // First frame after a WiFi upgrade: a PLAINTEXT CLIENT_INTRODUCTION. Ack
        // it in plaintext; the encrypted session (same keys/seq) resumes after.
        if self.awaiting_introduction {
            self.awaiting_introduction = false;
            use crate::location_nearby_connections as lnc;
            use lnc::bandwidth_upgrade_negotiation_frame as bwu;
            debug!("BWU: received introduction on WiFi channel; sending plaintext ACK");
            let ack = OfflineFrame {
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
            self.send_frame(ack.encode_to_vec()).await?;

            // Now that we're on WiFi, kick off the deferred sharing protocol.
            if self.wifi_upgrade_pending {
                self.wifi_upgrade_pending = false;
                self.send_paired_key_encryption().await?;
            }
            return Ok(());
        }

        let current_state = &self.state;
        // Now determine what will be the request type based on current state
        match current_state.state {
            State::Initial => {
                debug!("Handling State::Initial frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                let rdi = self.process_connection_request(&frame)?;
                info!("RemoteDeviceInfo: {:?}", &rdi);

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::ReceivedConnectionRequest;
                        e.remote_device_info = Some(rdi);
                    },
                    false,
                )
                .await;
            }
            State::ReceivedConnectionRequest => {
                debug!("Handling State::ReceivedConnectionRequest frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_init(&msg).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::SentUkeyServerInit;
                        e.client_init_msg_data = Some(frame_data);
                    },
                    false,
                )
                .await;
            }
            State::SentUkeyServerInit => {
                debug!("Handling State::SentUkeyServerInit frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_finish(&msg, &frame_data).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::ReceivedUkeyClientFinish;
                    },
                    false,
                )
                .await;
            }
            State::ReceivedUkeyClientFinish => {
                debug!("Handling State::ReceivedUkeyClientFinish frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                self.process_connection_response(&frame).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = State::SentConnectionResponse;
                    },
                    false,
                )
                .await;
            }
            _ => {
                if self.channel.is_some() {
                    // QS_BWU_ACTOR: the StreamChannel already stripped the framing
                    // AND decrypted + sequence-checked the d2d message, so
                    // `frame_data` is the inner OfflineFrame bytes — run the
                    // post-decode dispatch directly (no SecureMessage / seq advance
                    // here; the channel is the single sequence authority).
                    let offline =
                        location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                    self.process_decoded_offline_frame(&offline).await?;
                } else {
                    trace!("Handling SecureMessage frame");
                    let smsg = SecureMessage::decode(&*frame_data)?;
                    self.decrypt_and_process_secure_message(&smsg).await?;
                }
            }
        }

        Ok(())
    }

    fn process_connection_request(
        &self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<RemoteDeviceInfo, anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionRequest
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let connection_request = v1_frame
            .connection_request
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let endpoint_info = connection_request
            .endpoint_info
            .as_ref()
            .ok_or_else(|| anyhow!("Missing endpoint info"))?;

        // Check if endpoint info length is greater than 17
        if endpoint_info.len() <= 17 {
            return Err(anyhow!("Endpoint info too short"));
        }

        let device_name_length = endpoint_info[17] as usize;
        // Validate length including device name
        if endpoint_info.len() < device_name_length + 18 {
            return Err(anyhow!(
                "Endpoint info too short to contain the device name"
            ));
        }

        // Extract and validate device name based on length
        let device_name = std::str::from_utf8(&endpoint_info[18..(18 + device_name_length)])
            .map_err(|_| anyhow!("Device name is not valid UTF-8"))?;

        // Parsing the device type
        let raw_device_type = (endpoint_info[0] & 7) >> 1_usize;

        Ok(RemoteDeviceInfo {
            name: device_name.to_string(),
            device_type: DeviceType::from_raw_value(raw_device_type),
        })
    }

    async fn process_ukey2_client_init(&mut self, msg: &Ukey2Message) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientInit {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientInit",
                msg.message_type
            ));
        }

        let client_init = match Ukey2ClientInit::decode(msg.message_data()) {
            Ok(uk2ci) => uk2ci,
            Err(e) => {
                self.send_ukey2_alert(AlertType::BadMessageData).await?;
                return Err(anyhow!("UKey2: Ukey2ClientInit::decode: {}", e));
            }
        };

        if client_init.version() != 1 {
            self.send_ukey2_alert(AlertType::BadVersion).await?;
            return Err(anyhow!("UKey2: client_init.version != 1"));
        }

        if client_init.random().len() != 32 {
            self.send_ukey2_alert(AlertType::BadRandom).await?;
            return Err(anyhow!("UKey2: client_init.random.len != 32"));
        }

        // Searching for preferred cipher commitment
        let mut found = false;
        for commitment in &client_init.cipher_commitments {
            trace!("CipherCommitment: {:?}", commitment.handshake_cipher());
            if Ukey2HandshakeCipher::P256Sha512 == commitment.handshake_cipher() {
                found = true;
                self.update_state(
                    |e| {
                        e.cipher_commitment = Some(commitment.clone());
                    },
                    false,
                )
                .await;
                break;
            }
        }

        if !found {
            self.send_ukey2_alert(AlertType::BadHandshakeCipher).await?;
            return Err(anyhow!("UKey2: badHandshakeCipher"));
        }

        if client_init.next_protocol() != "AES_256_CBC-HMAC_SHA256" {
            self.send_ukey2_alert(AlertType::BadNextProtocol).await?;
            return Err(anyhow!(
                "UKey2: badNextProtocol: {}",
                client_init.next_protocol()
            ));
        }

        let (secret_key, public_key) = gen_ecdsa_keypair();

        let encoded_point = public_key.to_encoded_point(false);
        let x = encoded_point.x().unwrap();
        let y = encoded_point.y().unwrap();

        let pkey = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(EcP256PublicKey {
                x: encode_point(Bytes::from(x.to_vec()))?,
                y: encode_point(Bytes::from(y.to_vec()))?,
            }),
            ..Default::default()
        };

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
            public_key: Some(pkey.encode_to_vec()),
        };

        let server_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ServerInit.into()),
            message_data: Some(server_init.encode_to_vec()),
        };

        let server_init_data = server_init_msg.encode_to_vec();
        self.update_state(
            |e| {
                e.private_key = Some(secret_key);
                e.public_key = Some(public_key);
                e.server_init_data = Some(server_init_data.clone());
            },
            false,
        )
        .await;

        self.send_frame(server_init_data).await?;

        Ok(())
    }

    async fn process_ukey2_client_finish(
        &mut self,
        msg: &Ukey2Message,
        frame_data: &Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientFinish {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientFinish",
                msg.message_type
            ));
        }

        let sha512 = Sha512::digest(frame_data);
        if self.state.cipher_commitment.as_ref().unwrap().commitment() != sha512.as_slice() {
            error!("cipher_commitment isn't equals to sha512(frame_data)");
            return Err(anyhow!("UKey2: cipher_commitment != sha512"));
        }

        let client_finish = match Ukey2ClientFinished::decode(msg.message_data()) {
            Ok(uk2cf) => uk2cf,
            Err(e) => {
                return Err(anyhow!("UKey2: Ukey2ClientFinished::decode: {}", e));
            }
        };

        if client_finish.public_key.is_none() {
            return Err(anyhow!("UKey2: client_finish.public_key None"));
        }

        let client_public_key = match GenericPublicKey::decode(client_finish.public_key()) {
            Ok(cpk) => cpk,
            Err(e) => {
                return Err(anyhow!("UKey2: GenericPublicKey::decode: {}", e));
            }
        };

        self.finalize_key_exchange(client_public_key).await?;

        Ok(())
    }

    async fn process_connection_response(
        &mut self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionResponse
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let response = location_nearby_connections::OfflineFrame {
			version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
			v1: Some(location_nearby_connections::V1Frame {
				r#type: Some(location_nearby_connections::v1_frame::FrameType::ConnectionResponse.into()),
				connection_response: Some(location_nearby_connections::ConnectionResponseFrame {
					response: Some(location_nearby_connections::connection_response_frame::ResponseStatus::Accept.into()),
					os_info: Some(location_nearby_connections::OsInfo {
						r#type: Some(location_nearby_connections::os_info::OsType::Linux.into())
					}),
					..Default::default()
				}),
				..Default::default()
			})
		};

        self.send_frame(response.encode_to_vec()).await?;

        // QS_BWU_ACTOR: this plaintext connection_response is the last unencrypted
        // frame. Install the shared d2d session as the channel's cipher now, so the
        // first encrypted frame below (and every read/write after) is encrypted with
        // a continuous sequence — the channel becomes the single seq authority. The
        // phone won't send its next (encrypted) frame until it receives the
        // paired-key frame below, so the reader can't race ahead of this.
        if let (Some(channel), Some(session)) =
            (self.channel.as_ref(), self.state.session.as_ref())
        {
            channel.enable_encryption(session.clone());
        }

        // When a WiFi upgrade is pending, DON'T start the sharing protocol yet —
        // otherwise the phone replies on the L2CAP channel we're about to abandon,
        // and its sequence counter races ahead of ours. Send it after the upgrade.
        if !self.wifi_upgrade_pending {
            self.send_paired_key_encryption().await?;
        }

        Ok(())
    }

    async fn send_paired_key_encryption(&mut self) -> Result<(), anyhow::Error> {
        let paired_encryption = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyEncryption.into()),
                paired_key_encryption: Some(sharing_nearby::PairedKeyEncryptionFrame {
                    secret_id_hash: Some(gen_random(6)),
                    signed_data: Some(gen_random(72)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_encryption).await
    }

    async fn decrypt_and_process_secure_message(
        &mut self,
        smsg: &SecureMessage,
    ) -> Result<(), anyhow::Error> {
        // Delegate the d2d crypto to the shared session (byte-identical to the old
        // inline path); it returns the declared sequence + the inner frame bytes
        // without touching the counter, so the seq policy + trace below are unchanged.
        let session = self
            .state
            .session
            .clone()
            .ok_or_else(|| anyhow!("decrypt before UKEY2 session established"))?;
        let (recv_seq, frame_bytes) = session.decode_payload(smsg)?;

        let seq = self.get_client_seq_inc().await;
        // Decode the frame BEFORE the seq check so the trace shows the frame type
        // (critical for diagnosing the medium-switch channel drain).
        let offline = location_nearby_connections::OfflineFrame::decode(frame_bytes.as_slice())?;
        let rx_type = offline.v1.as_ref().and_then(|v| v.r#type).unwrap_or(0);
        let rx_bwu = offline
            .v1
            .as_ref()
            .and_then(|v| v.bandwidth_upgrade_negotiation.as_ref())
            .and_then(|b| b.event_type);
        trace!("RX d2d seq={recv_seq} (expect {seq}) frametype={rx_type} bwu_event={rx_bwu:?}");
        if recv_seq != seq {
            return Err(anyhow!(
                "Error d2d_msg.sequence_number invalid ({} vs {}) frametype={} bwu_event={:?}",
                recv_seq,
                seq,
                rx_type,
                rx_bwu
            ));
        }

        self.process_decoded_offline_frame(&offline).await
    }

    /// The post-decode dispatch for one decrypted `OfflineFrame`. Split out of
    /// `decrypt_and_process_secure_message` so the `QS_BWU_ACTOR` channel path —
    /// where the `StreamChannel` already decrypted + sequence-checked the frame —
    /// runs the identical dispatch without re-decrypting or re-advancing the d2d
    /// sequence (the channel/cipher already did both).
    async fn process_decoded_offline_frame(
        &mut self,
        offline: &OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = offline
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;
        match v1_frame.r#type() {
            location_nearby_connections::v1_frame::FrameType::PayloadTransfer => {
                trace!("Received FrameType::PayloadTransfer");
                let payload_transfer = v1_frame
                    .payload_transfer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                let header = payload_transfer
                    .payload_header
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;
                let chunk = payload_transfer
                    .payload_chunk
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                match header.r#type() {
                    payload_header::PayloadType::Bytes => {
                        trace!("Processing PayloadType::Bytes");
                        let payload_id = header.id();

                        if header.total_size() > SANE_FRAME_LENGTH.into() {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Payload too large: {} bytes",
                                header.total_size()
                            ));
                        }

                        self.state
                            .payload_buffers
                            .entry(payload_id)
                            .or_insert_with(|| Vec::with_capacity(header.total_size() as usize));

                        // Get the current length of the buffer, if it exists, without holding a mutable borrow.
                        let buffer_len = self.state.payload_buffers.get(&payload_id).unwrap().len();
                        if chunk.offset() != buffer_len as i64 {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Unexpected chunk offset: {}, expected: {}",
                                chunk.offset(),
                                buffer_len
                            ));
                        }

                        let buffer = self.state.payload_buffers.get_mut(&payload_id).unwrap();
                        if let Some(body) = &chunk.body {
                            buffer.extend(body);
                        }

                        if (chunk.flags() & 1) == 1 {
                            trace!("Chunk flags & 1 == 1 ?? End of data ??");

                            if self.state.text_payload.is_some()
                                && self.state.text_payload.as_ref().unwrap().get_i64_value()
                                    == payload_id
                            {
                                info!("Transfer finished");
                                let end_index =
                                    buffer.iter().position(|&b| b == 16).unwrap_or(buffer.len());
                                let payload = std::str::from_utf8(&buffer[..end_index])?.to_owned();

                                match self.state.text_payload.clone().unwrap() {
                                    TextPayloadInfo::Url(_) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload = Some(payload);
                                                    tmd.text_type = Some(TextPayloadType::Url);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    TextPayloadInfo::Text(_) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload = Some(payload);
                                                    tmd.text_type = Some(TextPayloadType::Text);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    TextPayloadInfo::Wifi((_, ssid)) => {
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.text_payload =
                                                        Some(format!("{ssid}: {}", payload.trim()));
                                                    tmd.text_type = Some(TextPayloadType::Wifi);
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                }

                                self.update_state(
                                    |e| {
                                        e.state = State::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            } else {
                                let innner_frame =
                                    sharing_nearby::Frame::decode(buffer.as_slice())?;
                                self.process_transfer_setup(&innner_frame).await?;
                            }
                        }
                    }
                    payload_header::PayloadType::File => {
                        trace!("Processing PayloadType::File");
                        let payload_id = header.id();

                        let file_internal = self
                            .state
                            .transferred_files
                            .get_mut(&payload_id)
                            .ok_or_else(|| {
                                anyhow!("File payload ID ({}) is not known", payload_id)
                            })?;

                        let current_offset = file_internal.bytes_transferred;
                        if chunk.offset() != current_offset {
                            return Err(anyhow!(
                                "Invalid offset into file {}, expected {}",
                                chunk.offset(),
                                current_offset
                            ));
                        }

                        let chunk_size = chunk.body().len();
                        if current_offset + chunk_size as i64 > file_internal.total_size {
                            return Err(anyhow!(
                                "Transferred file size exceeds previously specified value: {} vs {}", current_offset + chunk_size as i64, file_internal.total_size
                            ));
                        }

                        if !chunk.body().is_empty() {
                            file_internal
                                .file
                                .as_ref()
                                .unwrap()
                                .write_all_at(chunk.body(), current_offset as u64)?;
                            file_internal.bytes_transferred += chunk_size as i64;

                            self.update_state(
                                |e| {
                                    if let Some(tmd) = e.transfer_metadata.as_mut() {
                                        tmd.ack_bytes += chunk_size as u64;
                                    }
                                },
                                true,
                            )
                            .await;
                        } else if (chunk.flags() & 1) == 1 {
                            self.state.transferred_files.remove(&payload_id);
                            if self.state.transferred_files.is_empty() {
                                info!("Transfer finished");
                                self.update_state(
                                    |e| {
                                        e.state = State::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            }
                        }
                    }
                    payload_header::PayloadType::Stream => {
                        error!("Unhandled PayloadType::Stream: {:?}", header.r#type())
                    }
                    payload_header::PayloadType::UnknownPayloadType => {
                        error!(
                            "Invalid PayloadType::UnknownPayloadType: {:?}",
                            header.r#type()
                        )
                    }
                }
            }
            location_nearby_connections::v1_frame::FrameType::KeepAlive => {
                trace!("Sending keepalive");
                self.send_keepalive(true).await?;
            }
            location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeNegotiation => {
                // QS_BWU_ACTOR (Inc 2): the actor drives the upgrade handshake. Hand
                // it this negotiation frame (re-encoded into nearby-rs's proto, same
                // wire format) and return — the actor writes LAST_WRITE/SAFE_TO_CLOSE
                // and finalizes the channel swap; we never set the inline flags.
                if let Some(handle) = self.bwu_handle.clone() {
                    // Forward the negotiation frame (UPGRADE_FAILURE / LAST_WRITE /
                    // SAFE_TO_CLOSE / …) to the actor, which drives the handshake. The
                    // phone's STA-flap retry arrives as a separate FrameType::Bandwidth
                    // UpgradeRetry (handled below) and sets `wifi_retry_requested`.
                    use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame as bwu;
                    let event = v1_frame
                        .bandwidth_upgrade_negotiation
                        .as_ref()
                        .and_then(|b| b.event_type)
                        .unwrap_or(0);
                    // The phone's LAST_WRITE is its final OLD-channel frame — cue the
                    // l2cap driver to nudge + hand off to WiFi (it doesn't wait for the
                    // actor's SAFE_TO_CLOSE handshake, which the Pixel never completes).
                    if event == bwu::EventType::LastWriteToPriorChannel as i32 {
                        self.bwu_last_write_seen = true;
                    }
                    debug!("BWU(actor): forwarding negotiation event {event} to the actor");
                    let pb_frame = nearby_rs::proto::OfflineFrame::decode(
                        offline.encode_to_vec().as_slice(),
                    )
                    .map_err(|e| anyhow!("re-decode OfflineFrame for the BWU actor: {e}"))?;
                    handle
                        .incoming_frame(pb_frame, self.bwu_ep.clone(), NbMedium::BleL2cap)
                        .await;
                    return Ok(());
                }

                use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame as bwu;
                let event = v1_frame
                    .bandwidth_upgrade_negotiation
                    .as_ref()
                    .and_then(|b| b.event_type)
                    .unwrap_or(0);
                if event == bwu::EventType::ClientIntroduction as i32 {
                    debug!("BWU: received CLIENT_INTRODUCTION; sending ACK");
                    use crate::location_nearby_connections as lnc;
                    let ack = OfflineFrame {
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
                    self.encrypt_and_send(&ack).await?;
                } else if event == bwu::EventType::UpgradeFailure as i32 {
                    // Phone declined our WiFi offer. Dump the echoed frame (reveals
                    // the medium) and flag it so the driver reacts immediately.
                    info!(
                        "BWU: UPGRADE_FAILURE; frame = {:?}",
                        v1_frame.bandwidth_upgrade_negotiation
                    );
                    self.upgrade_rejected = true;
                } else if event == bwu::EventType::LastWriteToPriorChannel as i32 {
                    // Phone's final frame on the old (L2CAP) channel — now safe to
                    // switch to WiFi without losing an inbound d2d frame.
                    debug!("BWU: LAST_WRITE_TO_PRIOR_CHANNEL");
                    self.prior_channel_drained = true;
                } else {
                    debug!("BWU: received event {event}");
                }
            }
            location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeRetry => {
                // The phone's WiFi just recovered and it wants the upgrade again.
                // Flag it; the L2CAP driver re-offers WIFI_LAN.
                debug!("BWU: phone requested upgrade retry (WiFi recovered)");
                self.wifi_retry_requested = true;
            }
            _ => {
                error!("Unhandled offline frame encrypted: {:?}", offline);
            }
        }

        Ok(())
    }

    async fn process_transfer_setup(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() == sharing_nearby::v1_frame::FrameType::Cancel {
            info!("Transfer canceled");
            self.update_state(
                |e| {
                    e.state = State::Cancelled;
                },
                true,
            )
            .await;
            self.disconnection().await?;
            return Err(anyhow!(crate::errors::AppError::NotAnError));
        }

        match self.state.state {
            State::SentConnectionResponse => {
                debug!("Processing State::SentConnectionResponse");
                self.process_paired_key_encryption_frame(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = State::SentPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            State::SentPairedKeyResult => {
                debug!("Processing State::SentPairedKeyResult");
                self.process_paired_key_result(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = State::ReceivedPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            State::ReceivedPairedKeyResult => {
                debug!("Processing State::ReceivedPairedKeyResult");
                self.process_introduction(v1_frame).await?;
            }
            _ => {
                info!(
                    "Unhandled connection state in process_transfer_setup: {:?}",
                    self.state.state
                );
            }
        }

        Ok(())
    }

    async fn process_paired_key_encryption_frame(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_encryption.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        let paired_result = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyResult.into()),
                paired_key_result: Some(sharing_nearby::PairedKeyResultFrame {
                    status: Some(paired_key_result_frame::Status::Unable.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_result).await?;

        Ok(())
    }

    async fn process_paired_key_result(
        &self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_result.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        Ok(())
    }

    async fn process_introduction(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        let introduction = v1_frame
            .introduction
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        // No need to inform the channel here, we'll do it anyway with files info
        self.update_state(
            |e| {
                e.state = State::WaitingForUserConsent;
            },
            false,
        )
        .await;

        if !introduction.file_metadata.is_empty() && introduction.text_metadata.is_empty() {
            trace!("process_introduction: handling file_metadata");
            let mut files_name = Vec::with_capacity(introduction.file_metadata.len());
            let mut total_bytes: u64 = 0;

            for file in &introduction.file_metadata {
                info!("File name: {}", file.name());

                let mut dest = get_download_dir();
                dest.push(file.name());

                info!("Destination: {:?}", dest);
                if dest.exists() {
                    let mut counter = 1;
                    dest.pop();

                    loop {
                        dest.push(format!("{}_{}", counter, file.name()));
                        if !dest.exists() {
                            break;
                        }
                        dest.pop();
                        counter += 1;
                    }

                    info!("New destination: {:?}", dest);
                }

                let info = InternalFileInfo {
                    payload_id: file.payload_id(),
                    file_url: dest,
                    bytes_transferred: 0,
                    total_size: file.size(),
                    file: None,
                };
                total_bytes += info.total_size as u64;
                self.state.transferred_files.insert(file.payload_id(), info);
                files_name.push(file.name().to_owned());
            }

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                destination: Some(
                    get_download_dir()
                        .into_os_string()
                        .into_string()
                        .map_err(|_| anyhow!("failed to convert PathBuf to String"))?,
                ),
                source: self.state.remote_device_info.clone(),
                files: Some(files_name),
                pin_code: self.state.pin_code.clone(),
                text_description: None,
                total_bytes,
                ..Default::default()
            };

            info!("Asking for user consent: {:?}", metadata);
            self.update_state(
                |e| {
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else if introduction.text_metadata.len() == 1 {
            trace!("process_introduction: handling text_metadata");
            let meta = introduction.text_metadata.first().unwrap();

            match meta.r#type() {
                text_metadata::Type::Url => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        destination: None,
                        source: self.state.remote_device_info.clone(),
                        files: None,
                        pin_code: self.state.pin_code.clone(),
                        text_description: meta.text_title.clone(),
                        ..Default::default()
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Url(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::PhoneNumber
                | text_metadata::Type::Address
                | text_metadata::Type::Text => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        destination: None,
                        source: self.state.remote_device_info.clone(),
                        files: None,
                        pin_code: self.state.pin_code.clone(),
                        text_description: meta.text_title.clone(),
                        ..Default::default()
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Text(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::Unknown => {
                    // Reject transfer
                    self.reject_transfer(Some(
						sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
					))
					.await?;
                }
            }
        } else if introduction.wifi_credentials_metadata.len() == 1 {
            trace!("process_introduction: handling wifi_credentials_metadata");
            let meta = introduction.wifi_credentials_metadata.first().unwrap();

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                destination: None,
                source: self.state.remote_device_info.clone(),
                files: None,
                pin_code: self.state.pin_code.clone(),
                text_description: meta.ssid.clone(),
                ..Default::default()
            };

            self.update_state(
                |e| {
                    e.text_payload = Some(TextPayloadInfo::Wifi((
                        meta.payload_id(),
                        meta.ssid().to_owned(),
                    )));
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else {
            // Reject transfer
            self.reject_transfer(Some(
                sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
            ))
            .await?;
        }

        Ok(())
    }

    async fn disconnection(&mut self) -> Result<(), anyhow::Error> {
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await
        } else {
            self.send_frame(frame.encode_to_vec()).await
        }
    }

    async fn accept_transfer(&mut self) -> Result<(), anyhow::Error> {
        let ids: Vec<i64> = self.state.transferred_files.keys().cloned().collect();

        for id in ids {
            let mfi = self.state.transferred_files.get_mut(&id).unwrap();

            let file = File::create(&mfi.file_url)?;
            info!("Created file: {:?}", &file);
            mfi.file = Some(file);
        }

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sharing_nearby::connection_response_frame::Status::Accept.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        self.update_state(
            |e| {
                e.state = State::ReceivingFiles;
            },
            true,
        )
        .await;

        Ok(())
    }

    async fn reject_transfer(
        &mut self,
        reason: Option<sharing_nearby::connection_response_frame::Status>,
    ) -> Result<(), anyhow::Error> {
        let sreason = if let Some(r) = reason {
            r
        } else {
            sharing_nearby::connection_response_frame::Status::Reject
        };

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sreason.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        Ok(())
    }

    async fn finalize_key_exchange(
        &mut self,
        raw_peer_key: GenericPublicKey,
    ) -> Result<(), anyhow::Error> {
        let peer_p256_key = raw_peer_key
            .ec_p256_public_key
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let mut bytes = vec![0x04];
        // Ensure no more than 32 bytes for the keys
        if peer_p256_key.x.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.x[peer_p256_key.x.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.x);
        }
        if peer_p256_key.y.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.y[peer_p256_key.y.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.y);
        }

        let encoded_point = EncodedPoint::from_bytes(bytes)?;
        let peer_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
        let priv_key = self.state.private_key.as_ref().unwrap();

        let dhs = diffie_hellman(priv_key.to_nonzero_scalar(), peer_key.as_affine());
        let derived_secret = Sha256::digest(dhs.raw_secret_bytes());

        let mut ukey_info: Vec<u8> = vec![];
        ukey_info.extend_from_slice(self.state.client_init_msg_data.as_ref().unwrap());
        ukey_info.extend_from_slice(self.state.server_init_data.as_ref().unwrap());

        let auth_label = "UKEY2 v1 auth".as_bytes();
        let next_label = "UKEY2 v1 next".as_bytes();

        let auth_string = hkdf_extract_expand(auth_label, &derived_secret, &ukey_info, 32)?;
        let next_secret = hkdf_extract_expand(next_label, &derived_secret, &ukey_info, 32)?;

        let salt_hex = "82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510";
        let salt =
            hex::decode(salt_hex).map_err(|e| anyhow!("Failed to decode salt_hex: {}", e))?;

        let d2d_client = hkdf_extract_expand(&salt, &next_secret, "client".as_bytes(), 32)?;
        let d2d_server = hkdf_extract_expand(&salt, &next_secret, "server".as_bytes(), 32)?;

        let key_salt_hex = "BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E";
        let key_salt = hex::decode(key_salt_hex)
            .map_err(|e| anyhow!("Failed to decode key_salt_hex: {}", e))?;

        let client_key = hkdf_extract_expand(&key_salt, &d2d_client, "ENC:2".as_bytes(), 32)?;
        let client_hmac_key = hkdf_extract_expand(&key_salt, &d2d_client, "SIG:1".as_bytes(), 32)?;
        let server_key = hkdf_extract_expand(&key_salt, &d2d_server, "ENC:2".as_bytes(), 32)?;
        let server_hmac_key = hkdf_extract_expand(&key_salt, &d2d_server, "SIG:1".as_bytes(), 32)?;

        // The shared cipher session — the single source of truth for the keys and
        // the d2d sequence counters from here on. Built before the keys are moved
        // into InnerState so both stay in sync.
        let session = UkeySession::new(&server_key, &server_hmac_key, &client_key, &client_hmac_key)?;

        self.update_state(
            |e| {
                e.decrypt_key = Some(client_key);
                e.recv_hmac_key = Some(client_hmac_key);
                e.encrypt_key = Some(server_key);
                e.send_hmac_key = Some(server_hmac_key);
                e.session = Some(session);
                e.pin_code = Some(to_four_digit_string(&auth_string));
                e.encryption_done = true;
            },
            false,
        )
        .await;

        info!("Pin code: {:?}", self.state.pin_code);

        Ok(())
    }

    async fn send_ukey2_alert(&mut self, atype: AlertType) -> Result<(), anyhow::Error> {
        let alert = Ukey2Alert {
            r#type: Some(atype.into()),
            error_message: None,
        };

        let data = Ukey2Message {
            message_type: Some(atype.into()),
            message_data: Some(alert.encode_to_vec()),
        };

        self.send_frame(data.encode_to_vec()).await
    }

    async fn send_encrypted_frame(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let frame_data = frame.encode_to_vec();
        let body_size = frame_data.len();

        let payload_header = PayloadHeader {
            id: Some(rand::rng().random_range(i64::MIN..i64::MAX)),
            r#type: Some(payload_header::PayloadType::Bytes.into()),
            total_size: Some(body_size as i64),
            is_sensitive: Some(false),
            ..Default::default()
        };

        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(0),
                flags: Some(0),
                body: Some(frame_data),
            }),
            payload_header: Some(payload_header.clone()),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        // Send lastChunk
        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(body_size as i64),
                flags: Some(1), // lastChunk
                body: Some(vec![]),
            }),
            payload_header: Some(payload_header),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        Ok(())
    }

    async fn encrypt_and_send(&mut self, frame: &OfflineFrame) -> Result<(), anyhow::Error> {
        // QS_BWU_ACTOR: the StreamChannel owns encryption + the d2d sequence. Hand
        // it the plaintext OfflineFrame; its cipher (the shared UkeySession) encodes
        // (encrypt + advance server_seq) and frames it. No inline seq advance here.
        if let Some(channel) = self.channel.as_ref() {
            return exception_to_result(channel.write(&frame.encode_to_vec()));
        }

        let tx_seq = self.get_server_seq_inc().await;
        let tx_type = frame.v1.as_ref().and_then(|v| v.r#type).unwrap_or(0);
        let tx_bwu = frame
            .v1
            .as_ref()
            .and_then(|v| v.bandwidth_upgrade_negotiation.as_ref())
            .and_then(|b| b.event_type);
        trace!("TX d2d seq={tx_seq} frametype={tx_type} bwu_event={tx_bwu:?}");

        // Delegate the d2d crypto to the shared session (byte-identical to the old
        // inline path). tx_seq was just advanced via the same session.
        let session = self
            .state
            .session
            .clone()
            .ok_or_else(|| anyhow!("encrypt_and_send before UKEY2 session established"))?;
        let smsg_bytes = session.encode_payload(&frame.encode_to_vec(), tx_seq, &gen_random(16));

        self.send_frame(smsg_bytes).await?;

        Ok(())
    }

    async fn send_keepalive(&mut self, ack: bool) -> Result<(), anyhow::Error> {
        let ack_frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::KeepAlive.into()),
                keep_alive: Some(KeepAliveFrame { ack: Some(ack) }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&ack_frame).await
        } else {
            self.send_frame(ack_frame.encode_to_vec()).await
        }
    }

    async fn send_frame(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        // QS_BWU_ACTOR: route the raw frame through the StreamChannel, which adds
        // the 4B length framing. During the UKEY2 handshake the channel cipher is
        // off, so this is a plaintext send (byte-identical to the inline path); it
        // is only used pre-encryption, so the channel never double-encrypts here.
        if let Some(channel) = self.channel.as_ref() {
            return exception_to_result(channel.write(&data));
        }

        let length = data.len();

        // Prepare length prefix in big-endian format
        let length_bytes = [
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];

        let mut prefixed_length = Vec::with_capacity(length + 4);
        prefixed_length.extend_from_slice(&length_bytes);
        prefixed_length.extend_from_slice(&data);

        self.socket.write_all(&prefixed_length).await?;
        self.socket.flush().await?;

        Ok(())
    }

    async fn get_server_seq_inc(&mut self) -> i32 {
        // The session is authoritative once UKEY2 completes (so the sequence is
        // continuous across the medium swap); state.server_seq mirrors it.
        let next = match self.state.session.as_ref() {
            Some(s) => s.next_server_seq(),
            None => self.state.server_seq + 1,
        };
        self.update_state(|e| e.server_seq = next, false).await;
        self.state.server_seq
    }

    async fn get_client_seq_inc(&mut self) -> i32 {
        let next = match self.state.session.as_ref() {
            Some(s) => s.next_client_seq(),
            None => self.state.client_seq + 1,
        };
        self.update_state(|e| e.client_seq = next, false).await;
        self.state.client_seq
    }

    async fn update_state<F>(&mut self, f: F, inform: bool)
    where
        F: FnOnce(&mut InnerState),
    {
        f(&mut self.state);

        if !inform {
            return;
        }

        trace!("Sending msg into the channel");
        let _ = self.sender.send(ChannelMessage {
            id: self.state.id.clone(),
            direction: ChannelDirection::LibToFront,
            rtype: Some(crate::channel::TransferType::Inbound),
            state: Some(self.state.state.clone()),
            meta: self.state.transfer_metadata.clone(),
            ..Default::default()
        });
        // Add a small sleep timer to allow the Tokio runtime to have
        // some spare time to process channel's message. Otherwise it
        // get spammed by new requests. Currently set to 10 micro secs.
        tokio::time::sleep(SANITY_DURATION).await;
    }
}

/// rqs_lib's hand-rolled WIFI_LAN `UPGRADE_PATH_AVAILABLE` offer (the proven,
/// Pixel-accepted frame).
fn beamish_wifi_upgrade_frame(ip: [u8; 4], port: u16) -> OfflineFrame {
    use crate::location_nearby_connections as lnc;
    use lnc::bandwidth_upgrade_negotiation_frame as bwu;

    OfflineFrame {
        version: Some(lnc::offline_frame::Version::V1.into()),
        v1: Some(lnc::V1Frame {
            r#type: Some(lnc::v1_frame::FrameType::BandwidthUpgradeNegotiation.into()),
            bandwidth_upgrade_negotiation: Some(lnc::BandwidthUpgradeNegotiationFrame {
                event_type: Some(bwu::EventType::UpgradePathAvailable.into()),
                upgrade_path_info: Some(bwu::UpgradePathInfo {
                    medium: Some(bwu::upgrade_path_info::Medium::WifiLan.into()),
                    wifi_lan_socket: Some(bwu::upgrade_path_info::WifiLanSocket {
                        ip_address: Some(ip.to_vec()),
                        wifi_port: Some(port as i32),
                        address_candidates: vec![lnc::ServiceAddress {
                            ip_address: Some(ip.to_vec()),
                            port: Some(port as i32),
                        }],
                    }),
                    supports_client_introduction_ack: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

/// The same offer, built by the nearby-rs port (golden-tested against Google's
/// `offline_frames.cc::ForBwuWifiLanPathAvailable`) and re-decoded into our
/// proto type. Used to validate the port's WIFI_LAN frame against the Pixel.
fn nearby_rs_wifi_upgrade_frame(ip: [u8; 4], port: u16) -> OfflineFrame {
    let bytes = nearby_rs::frames::for_bwu_wifi_lan_path_available(&[
        nearby_rs::frames::ServiceAddress {
            address: ip.to_vec(),
            port: port as i32,
        },
    ]);
    OfflineFrame::decode(bytes.as_slice())
        .expect("nearby-rs UPGRADE_PATH_AVAILABLE decodes as our OfflineFrame")
}

#[cfg(test)]
mod nearby_rs_conformance {
    use super::*;

    #[test]
    fn nearby_rs_wifi_upgrade_frame_is_byte_identical_to_ours() {
        let ip = [192, 168, 1, 5];
        let port = 49152u16;

        let ours = beamish_wifi_upgrade_frame(ip, port);
        let theirs = nearby_rs_wifi_upgrade_frame(ip, port);

        // Same structure...
        assert_eq!(ours, theirs);
        // ...and byte-identical on the wire (what the Pixel actually sees).
        let mut a = Vec::new();
        ours.encode(&mut a).unwrap();
        let mut b = Vec::new();
        theirs.encode(&mut b).unwrap();
        assert_eq!(a, b, "nearby-rs WIFI_LAN offer differs from the proven one");
    }
}
