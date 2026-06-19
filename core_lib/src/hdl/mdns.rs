use std::net::{IpAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use get_if_addrs::{get_if_addrs, IfAddr};
use mdns_sd::{AddrType, ServiceDaemon, ServiceInfo};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Receiver;
use tokio::sync::watch;
use tokio::time::{interval_at, Instant};
use tokio_util::sync::CancellationToken;
use ts_rs::TS;

use crate::utils::{gen_mdns_endpoint_info, gen_mdns_name, DeviceType};

const INNER_NAME: &str = "MDnsServer";
const TICK_INTERVAL: Duration = Duration::from_secs(60);
// While discoverable, proactively re-multicast our record on this cadence so a
// phone that begins its Quick Share discovery AFTER we registered still learns
// our WiFi endpoint (IP:port). Without it the phone only has our record if it
// happened to be listening at our one startup announcement — the main cause of
// "discovered over BLE, but tap-to-send never connects".
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub enum Visibility {
    Visible = 0,
    Invisible = 1,
    Temporarily = 2,
}

#[allow(dead_code)]
impl Visibility {
    pub fn from_raw_value(value: u64) -> Self {
        match value {
            0 => Visibility::Visible,
            1 => Visibility::Invisible,
            2 => Visibility::Temporarily,
            _ => unreachable!(),
        }
    }
}

pub struct MDnsServer {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    ble_receiver: Receiver<()>,
    visibility_sender: Arc<Mutex<watch::Sender<Visibility>>>,
    visibility_receiver: watch::Receiver<Visibility>,
}

impl MDnsServer {
    pub fn new(
        endpoint_id: [u8; 4],
        service_port: u16,
        ble_receiver: Receiver<()>,
        visibility_sender: Arc<Mutex<watch::Sender<Visibility>>>,
        visibility_receiver: watch::Receiver<Visibility>,
    ) -> Result<Self, anyhow::Error> {
        let service_info = Self::build_service(endpoint_id, service_port, DeviceType::Laptop)?;

        Ok(Self {
            daemon: ServiceDaemon::new()?,
            service_info,
            ble_receiver,
            visibility_sender,
            visibility_receiver,
        })
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");
        let monitor = self.daemon.monitor()?;
        let ble_receiver = &mut self.ble_receiver;
        let mut visibility = *self.visibility_receiver.borrow();
        let mut interval = interval_at(Instant::now() + TICK_INTERVAL, TICK_INTERVAL);
        let mut reannounce =
            interval_at(Instant::now() + REANNOUNCE_INTERVAL, REANNOUNCE_INTERVAL);

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                r = monitor.recv_async() => {
                    match r {
                        Ok(_) => continue,
                        Err(err) => return Err(err.into()),
                    }
                },
                _ = self.visibility_receiver.changed() => {
                    visibility = *self.visibility_receiver.borrow_and_update();

                    debug!("{INNER_NAME}: visibility changed: {visibility:?}");
                    if visibility == Visibility::Visible {
                        self.daemon.register(self.service_info.clone())?;
                    } else if visibility == Visibility::Invisible {
                        let receiver = self.daemon.unregister(self.service_info.get_fullname())?;
                        let _ = receiver.recv();
                    } else if visibility == Visibility::Temporarily {
                        self.daemon.register(self.service_info.clone())?;
                        interval.reset();
                    }
                }
                _ = ble_receiver.recv() => {
                    if visibility == Visibility::Invisible {
                        continue;
                    }

                    debug!("{INNER_NAME}: ble_receiver: got event");
                    if visibility == Visibility::Visible || visibility == Visibility::Temporarily {
                        // Android can sometime not see the mDNS service if the service
                        // was running BEFORE Android started the Discovery phase for QuickShare.
                        // So resend a broadcast if there's a android device sending.
                        self.daemon.register_resend(self.service_info.get_fullname())?;
                    } else {
                        self.daemon.register(self.service_info.clone())?;
                    }
                },
                _ = reannounce.tick() => {
                    if visibility == Visibility::Visible || visibility == Visibility::Temporarily {
                        debug!("{INNER_NAME}: periodic re-announce");
                        let _ = self.daemon.register_resend(self.service_info.get_fullname());
                    }
                }
                _ = interval.tick() => {
                    if visibility != Visibility::Temporarily {
                        continue;
                    }

                    let receiver = self.daemon.unregister(self.service_info.get_fullname())?;
                    let _ = receiver.recv();
                    let _ = self.visibility_sender.lock().unwrap().send(Visibility::Invisible);
                }
            }
        }

        // Unregister the mDNS service - we're shutting down
        let receiver = self.daemon.unregister(self.service_info.get_fullname())?;
        if let Ok(event) = receiver.recv() {
            info!("MDnsServer: service unregistered: {:?}", &event);
        }

        Ok(())
    }

    fn build_service(
        endpoint_id: [u8; 4],
        service_port: u16,
        device_type: DeviceType,
    ) -> Result<ServiceInfo, anyhow::Error> {
        let name = gen_mdns_name(endpoint_id);
        let hostname = sys_metrics::host::get_hostname()?;
        info!("Broadcasting with: {hostname}");
        let endpoint_info = gen_mdns_endpoint_info(device_type as u8, &hostname);

        // Use a UNIQUE mDNS host name for the SRV target instead of the bare
        // system hostname. avahi-daemon (if running) also claims "<host>.local"
        // and answers it with EVERY interface address — docker/lxc/VPN IPv4 and
        // IPv6 ULAs included. A phone resolving our SRV target would then get
        // avahi's unreachable address instead of the LAN IP we pin below, and
        // the connection fails right after discovery. A per-endpoint host name
        // is served only by us, with only the address(es) we set here.
        // Must be a fully-qualified ".local." name: mdns-sd uses host_name
        // verbatim as the SRV target and A-record owner (it does NOT append the
        // domain), and Android's resolver only resolves names in .local.
        let mdns_host = format!(
            "quickshare-{:02x}{:02x}{:02x}{:02x}.local.",
            endpoint_id[0], endpoint_id[1], endpoint_id[2], endpoint_id[3]
        );

        let properties = [("n", endpoint_info)];

        // Publish ONLY the real LAN address(es). enable_addr_auto() advertises
        // EVERY interface (docker0, lxcbr0, veth*, VPNs, ...). A phone that
        // discovered us over BLE then tries to connect over WiFi-LAN, and if it
        // picks one of those unreachable IPs the connection fails even though
        // discovery worked — which looks like "listed but tap fails", and only
        // succeeds when it happens to try the right IP. So pin the address to
        // the one the OS actually uses to reach the LAN.
        let lan_ips = lan_ipv4s();
        let si = if lan_ips.is_empty() {
            warn!(
                "{INNER_NAME}: no LAN IPv4 found; falling back to addr_auto (may publish unreachable IPs)"
            );
            ServiceInfo::new(
                "_FC9F5ED42C8A._tcp.local.",
                &name,
                &mdns_host,
                "",
                service_port,
                &properties[..],
            )?
            .enable_addr_auto(AddrType::V4)
        } else {
            info!("{INNER_NAME}: advertising LAN address(es): {}", lan_ips.join(","));
            ServiceInfo::new(
                "_FC9F5ED42C8A._tcp.local.",
                &name,
                &mdns_host,
                &lan_ips[..],
                service_port,
                &properties[..],
            )?
        };

        Ok(si)
    }
}

/// Returns the host's real LAN IPv4 address(es), excluding loopback and virtual
/// interfaces (docker/lxc/veth/VPN/...). Prefers the source address the OS would
/// use to reach off-link hosts — i.e. the interface the phone is also on.
fn lan_ipv4s() -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();

    // Put the routing-table source IP first: the interface the OS uses to reach
    // off-link hosts, i.e. the one a LAN phone is almost always on. Connecting a
    // UDP socket sends no packet; it just binds the matching source address.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let IpAddr::V4(ip) = local.ip() {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }

    // Add every other real (non-loopback, non-virtual) LAN IPv4 so a host with
    // more than one physical NIC is reachable on whichever one the phone shares.
    // Virtual bridges/tunnels (docker/lxc/veth/VPN/...) are excluded so we never
    // advertise an address the phone can't route to.
    if let Ok(if_addrs) = get_if_addrs() {
        for i in if_addrs {
            if i.is_loopback() || is_virtual_iface(&i.name) {
                continue;
            }
            if let IfAddr::V4(v) = i.addr {
                let s = v.ip.to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
            }
        }
    }

    ips
}

/// Interface name prefixes for bridges/tunnels/VPNs a phone can't route to.
fn is_virtual_iface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "docker", "br-", "lxc", "lxd", "veth", "virbr", "vmnet", "tun", "tap",
        "wg", "zt", "tailscale", "kube", "cni", "flannel", "vboxnet",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}
