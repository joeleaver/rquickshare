#[macro_use]
extern crate log;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::anyhow;
use channel::ChannelMessage;
#[cfg(all(feature = "experimental", target_os = "linux"))]
use hdl::BleAdvertiser;
#[cfg(all(feature = "experimental", target_os = "linux"))]
use hdl::BleConnectionsAdvertiser;
#[cfg(all(feature = "experimental", target_os = "linux"))]
use hdl::BleDiscovery;
use hdl::MDnsDiscovery;
use once_cell::sync::Lazy;
use rand::distr::Alphanumeric;
use rand::Rng;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[cfg(feature = "experimental")]
use crate::hdl::BleListener;
use crate::hdl::MDnsServer;
use crate::manager::TcpServer;

pub mod channel;
mod errors;
mod hdl;
mod manager;
mod utils;

pub use hdl::{EndpointInfo, OutboundPayload, State, Visibility};
pub use manager::SendInfo;
pub use utils::DeviceType;

pub mod sharing_nearby {
    include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
}

pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

pub mod location_nearby_connections {
    include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
}

static CUSTOM_DOWNLOAD: Lazy<RwLock<Option<PathBuf>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug)]
pub struct RQS {
    tracker: Option<TaskTracker>,
    ctoken: Option<CancellationToken>,
    // Discovery token is different than ctoken because he is on his own
    // - can be cancelled while the ctoken is still active
    discovery_ctk: Option<CancellationToken>,

    // Used to trigger a change in the mDNS visibility (and later on, BLE)
    pub visibility_sender: Arc<Mutex<watch::Sender<Visibility>>>,
    visibility_receiver: watch::Receiver<Visibility>,

    // Only used to send the info "a nearby device is sharing"
    ble_sender: broadcast::Sender<()>,

    port_number: Option<u32>,

    pub message_sender: broadcast::Sender<ChannelMessage>,
}

impl Default for RQS {
    fn default() -> Self {
        Self::new(Visibility::Visible, None, None)
    }
}

impl RQS {
    pub fn new(
        visibility: Visibility,
        port_number: Option<u32>,
        download_path: Option<PathBuf>,
    ) -> Self {
        let mut guard = CUSTOM_DOWNLOAD.write().unwrap();
        *guard = download_path;

        let (message_sender, _) = broadcast::channel(50);
        let (ble_sender, _) = broadcast::channel(5);

        // Define default visibility as per the args inside the new()
        let (visibility_sender, visibility_receiver) = watch::channel(Visibility::Invisible);
        let _ = visibility_sender.send(visibility);

        Self {
            tracker: None,
            ctoken: None,
            discovery_ctk: None,
            visibility_sender: Arc::new(Mutex::new(visibility_sender)),
            visibility_receiver,
            ble_sender,
            port_number,
            message_sender,
        }
    }

    pub async fn run(
        &mut self,
    ) -> Result<(mpsc::Sender<SendInfo>, broadcast::Receiver<()>), anyhow::Error> {
        let tracker = TaskTracker::new();
        let ctoken = CancellationToken::new();
        self.tracker = Some(tracker.clone());
        self.ctoken = Some(ctoken.clone());

        // Stable per-machine endpoint_id so app restarts don't leave ghost
        // entries on the sender's device. Falls back to random.
        //
        // QS_RANDOM_ENDPOINT=1 forces a fresh random endpoint_id each launch — used
        // to test whether the phone keeps a per-endpoint negative cache that refuses
        // the WiFi bandwidth upgrade after our earlier broken upgrades to this stable
        // endpoint_id failed (see memory [[quickshare-wifi-upgrade-research]]).
        let random_endpoint = || -> Vec<u8> {
            rand::rng()
                .sample_iter(Alphanumeric)
                .take(4)
                .map(u8::from)
                .collect()
        };
        let endpoint_id: Vec<u8> = if std::env::var_os("QS_RANDOM_ENDPOINT").is_some() {
            let id = random_endpoint();
            info!("QS_RANDOM_ENDPOINT set; using random endpoint_id {id:?}");
            id
        } else {
            std::fs::read_to_string("/etc/machine-id")
                .ok()
                .map(|s| s.trim().bytes().take(4).collect::<Vec<u8>>())
                .filter(|v| v.len() == 4)
                .unwrap_or_else(random_endpoint)
        };
        let tcp_listener =
            TcpListener::bind(format!("0.0.0.0:{}", self.port_number.unwrap_or(0))).await?;
        let binded_addr = tcp_listener.local_addr()?;
        info!("TcpListener on: {}", binded_addr);

        // MPSC for the TcpServer
        let send_channel = mpsc::channel(10);
        // Start TcpServer in own "task"
        let mut server = TcpServer::new(
            endpoint_id[..4].try_into()?,
            tcp_listener,
            self.message_sender.clone(),
            send_channel.1,
        )?;
        let ctk = ctoken.clone();
        tracker.spawn(async move { server.run(ctk).await });

        #[cfg(feature = "experimental")]
        {
            // Don't threat BleListener error as fatal, it's a nice to have.
            if let Ok(ble) = BleListener::new(self.ble_sender.clone()).await {
                let ctk = ctoken.clone();
                tracker.spawn(async move { ble.run(ctk).await });
            }
        }

        // Start MDnsServer in own "task"
        let mut mdns = MDnsServer::new(
            endpoint_id[..4].try_into()?,
            binded_addr.port(),
            self.ble_sender.subscribe(),
            self.visibility_sender.clone(),
            self.visibility_receiver.clone(),
        )?;
        let ctk = ctoken.clone();
        tracker.spawn(async move { mdns.run(ctk).await });

        // Advertise as a discoverable Quick Share RECEIVER over BLE (0xFEF3).
        //
        // ON BY DEFAULT (2026-06-18). This runs the L2CAP CoC server + BLE advert
        // so the phone can discover us over Bluetooth and bandwidth-upgrade to
        // WiFi-LAN (reliable discovery + WiFi speed, and works when mDNS discovery
        // fails). The historical "advert is harmful" failure (phone tried a BT
        // transport we didn't serve) is gone now that we serve L2CAP and complete
        // the WiFi upgrade. mDNS still works in parallel. Opt out with
        // QS_NO_BLE_ADVERT=1 to fall back to pure mDNS+TCP (NearDrop-style).
        #[cfg(all(feature = "experimental", target_os = "linux"))]
        if std::env::var_os("QS_NO_BLE_ADVERT").is_none() {
            let eid: [u8; 4] = endpoint_id[..4].try_into()?;
            let device_name =
                sys_metrics::host::get_hostname().unwrap_or_else(|_| "rquickshare".to_string());

            // Inner BleAdvertisement built ONCE and shared so the advert header's
            // hash matches what the L2CAP server returns for REQUEST_ADVERTISEMENT.
            let psm = hdl::L2CAP_PSM;
            let inner = hdl::build_inner_advertisement(eid, &device_name, psm);

            // L2CAP CoC server for the BLE transport, advertised via the PSM
            // above so the phone will attempt an L2CAP connection.
            let ctk = ctoken.clone();
            let inner_l2 = inner.clone();
            let l2_sender = self.message_sender.clone();
            tracker.spawn(async move {
                if let Err(e) = hdl::L2capServer::new(psm, inner_l2, l2_sender).run(ctk).await {
                    error!("L2capServer error: {e}");
                }
            });

            match BleConnectionsAdvertiser::new(eid, device_name, psm, inner).await {
                Ok(adv) => {
                    let ctk = ctoken.clone();
                    tracker.spawn(async move {
                        if let Err(e) = adv.run(ctk).await {
                            error!("BleConnectionsAdvertiser error: {e}");
                        }
                    });
                }
                Err(e) => error!("Couldn't init BleConnectionsAdvertiser: {e}"),
            }
        }

        tracker.close();

        Ok((send_channel.0, self.ble_sender.subscribe()))
    }

    pub fn discovery(
        &mut self,
        sender: broadcast::Sender<EndpointInfo>,
    ) -> Result<(), anyhow::Error> {
        let tracker = self
            .tracker
            .as_ref()
            .ok_or_else(|| anyhow!("The service wasn't first started"))?;

        let ctk = CancellationToken::new();
        self.discovery_ctk = Some(ctk.clone());

        #[cfg(all(feature = "experimental", target_os = "linux"))]
        {
            let ctk_blea = ctk.clone();
            tracker.spawn(async move {
                let blea = match BleAdvertiser::new().await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Couldn't init BleAdvertiser: {}", e);
                        return;
                    }
                };

                if let Err(e) = blea.run(ctk_blea).await {
                    error!("Couldn't start BleAdvertiser: {}", e);
                }
            });

            // Scan BLE for phones that are only "visible to everyone" (Nearby
            // Presence 0xFEF3, no mDNS) and feed them into the same discovery
            // stream so they appear alongside the mDNS/WiFi endpoints.
            let ctk_bd = ctk.clone();
            let bd_sender = sender.clone();
            tracker.spawn(async move {
                match BleDiscovery::new(bd_sender).await {
                    Ok(bd) => {
                        if let Err(e) = bd.run(ctk_bd).await {
                            error!("Couldn't start BleDiscovery: {}", e);
                        }
                    }
                    Err(e) => error!("Couldn't init BleDiscovery: {}", e),
                }
            });
        }

        let discovery = MDnsDiscovery::new(sender)?;
        tracker.spawn(async move { discovery.run(ctk.clone()).await });

        Ok(())
    }

    pub fn stop_discovery(&mut self) {
        if let Some(discovert_ctk) = &self.discovery_ctk {
            discovert_ctk.cancel();
            self.discovery_ctk = None;
        }
    }

    pub fn change_visibility(&mut self, nv: Visibility) {
        self.visibility_sender
            .lock()
            .unwrap()
            .send_modify(|state| *state = nv);
    }

    pub async fn stop(&mut self) {
        self.stop_discovery();

        if let Some(ctoken) = &self.ctoken {
            ctoken.cancel();
        }

        if let Some(tracker) = &self.tracker {
            tracker.wait().await;
        }

        self.ctoken = None;
        self.tracker = None;
    }

    // Setting None here will resume the default settings
    pub fn set_download_path(&self, p: Option<PathBuf>) {
        debug!("Setting the download path to {:?}", p);
        let mut guard = CUSTOM_DOWNLOAD.write().unwrap();
        *guard = p;
    }
}
