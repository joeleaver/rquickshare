//! `NmSoftAp` — the Linux platform implementation of the nearby-rs
//! [`SoftAp`](nearby_rs::bwu::SoftAp) seam, for the WIFI_HOTSPOT bandwidth upgrade
//! (Phase 4). beamish is the BWU **initiator** on the receive path, so this stands
//! up a SoftAP the phone joins as a STA; the responder methods (join/leave an AP)
//! are stubs for now (used only by a future send-side WIFI_DIRECT/HOTSPOT path).
//!
//! ## What it does on [`start`](SoftAp::start)
//! 1. Detect the connected Wi-Fi STA interface (e.g. `wlp195s0`) and its current
//!    frequency. The MT7925 (and most single-radio chips) can only run a SoftAP on
//!    the **same channel** as the STA, so we pin the AP co-channel.
//! 2. Create an `__ap` virtual interface (e.g. `ap0`) via the privileged vif
//!    backend ([`VifBackend`]) — the one operation that needs `CAP_NET_ADMIN`.
//! 3. Hand the vif to NetworkManager (`device set <ap> managed yes`), add a
//!    user-owned AP connection (mode=ap, band/channel pinned, WPA2-PSK,
//!    `ipv4.method=shared` → NAT + dnsmasq DHCP, gateway `10.42.0.1`), and bring it
//!    up. Activating a user-owned connection in an active session needs no polkit
//!    prompt.
//! 4. Return [`HotspotCreds`] (SSID/PSK/frequency/gateway) for the
//!    `UPGRADE_PATH_AVAILABLE` offer.
//!
//! [`stop`](SoftAp::stop) tears the NM connection down + deletes it, then deletes
//! the vif.
//!
//! ## First cut: `iw` + `nmcli`
//! This shells out to `iw`/`ip`/`nmcli` (faithful to the validated Phase-0 spike).
//! The privileged vif step defaults to `sudo iw` (works today with passwordless
//! sudo); set `QS_HOTSPOT_VIF_HELPER=/path/to/helper` to use a `pkexec`-invoked
//! `CAP_NET_ADMIN` helper instead (the shippable path — task #21). A native
//! NetworkManager-over-D-Bus implementation is a later refinement.
//!
//! ## Env overrides
//! * `QS_HOTSPOT_STA_IFACE` — force the STA interface (skip detection).
//! * `QS_HOTSPOT_AP_IFACE` — the `__ap` vif name to create (default `ap0`).
//! * `QS_HOTSPOT_VIF_HELPER` — absolute path to the privileged vif helper; when
//!   set, vif add/del go through `pkexec <helper> add|del …` instead of `sudo iw`.

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;

use log::{debug, info, warn};
use nearby_rs::bwu::{HotspotCreds, SoftAp};
use rand::RngCore;

/// The NM connection name we create/own (deterministic so teardown is exact).
const NM_CON_NAME: &str = "beamish-hotspot";
/// NetworkManager's default gateway for an `ipv4.method=shared` connection.
const SHARED_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
/// Where beamish packaging installs the privileged vif helper. When present we
/// use it (via `pkexec` + polkit, no password for an active session) in preference
/// to `sudo iw`; overridable with `QS_HOTSPOT_VIF_HELPER`.
const DEFAULT_VIF_HELPER: &str = "/usr/libexec/beamish-vif-helper";

/// How to create/delete the privileged `__ap` virtual interface.
#[derive(Clone, Debug)]
enum VifBackend {
    /// `sudo iw …` — the dev default (passwordless sudo on the dev box).
    SudoIw,
    /// `pkexec <helper> add|del …` — the shippable path (CAP_NET_ADMIN helper +
    /// polkit `.policy`, task #21).
    Helper(String),
}

/// Per-activation state, set on [`start`](SoftAp::start), cleared on
/// [`stop`](SoftAp::stop).
struct ApState {
    ssid: String,
}

/// Linux SoftAP via NetworkManager + a privileged vif helper.
pub struct NmSoftAp {
    sta_iface: String,
    ap_iface: String,
    vif: VifBackend,
    state: Mutex<Option<ApState>>,
}

impl NmSoftAp {
    /// Construct, detecting the connected Wi-Fi STA interface (overridable via
    /// `QS_HOTSPOT_STA_IFACE`). Returns `None` if no connected Wi-Fi device is
    /// found — the caller then falls back to WIFI_LAN.
    pub fn new() -> Option<Self> {
        let sta_iface = match std::env::var("QS_HOTSPOT_STA_IFACE") {
            Ok(s) if !s.is_empty() => s,
            _ => detect_connected_wifi_iface()?,
        };
        let ap_iface = std::env::var("QS_HOTSPOT_AP_IFACE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "ap0".to_string());
        // Prefer the installed pkexec helper (the shippable path) when present;
        // an explicit QS_HOTSPOT_VIF_HELPER overrides; else fall back to `sudo iw`
        // for dev boxes with passwordless sudo.
        let vif = match std::env::var("QS_HOTSPOT_VIF_HELPER") {
            Ok(p) if !p.is_empty() => VifBackend::Helper(p),
            _ if std::path::Path::new(DEFAULT_VIF_HELPER).exists() => {
                VifBackend::Helper(DEFAULT_VIF_HELPER.to_string())
            }
            _ => VifBackend::SudoIw,
        };
        info!("NmSoftAp: STA iface {sta_iface}, AP vif {ap_iface}, vif backend {vif:?}");
        Some(Self {
            sta_iface,
            ap_iface,
            vif,
            state: Mutex::new(None),
        })
    }

    /// Create the `__ap` vif and bring it up (privileged). Idempotent: deletes any
    /// stale vif of the same name first.
    fn create_vif(&self) -> Result<(), String> {
        // Best-effort cleanup of a stale vif from a crashed prior run.
        let _ = self.delete_vif();
        match &self.vif {
            VifBackend::SudoIw => {
                run(
                    "sudo",
                    &[
                        "iw",
                        "dev",
                        &self.sta_iface,
                        "interface",
                        "add",
                        &self.ap_iface,
                        "type",
                        "__ap",
                    ],
                )?;
                run("sudo", &["ip", "link", "set", &self.ap_iface, "up"])?;
            }
            VifBackend::Helper(path) => {
                run("pkexec", &[path, "add", &self.sta_iface, &self.ap_iface])?;
            }
        }
        Ok(())
    }

    /// Delete the `__ap` vif (privileged). Best-effort; errors are logged, not
    /// propagated (teardown must not fail loudly).
    fn delete_vif(&self) -> Result<(), String> {
        match &self.vif {
            VifBackend::SudoIw => run("sudo", &["iw", "dev", &self.ap_iface, "del"]).map(|_| ()),
            VifBackend::Helper(path) => run("pkexec", &[path, "del", &self.ap_iface]).map(|_| ()),
        }
    }

    /// Unconditional best-effort teardown: bring down + delete the NM connection,
    /// return the vif to NM-unmanaged (so a vif that survives deletion isn't left
    /// managed), then delete the vif. Idempotent — safe to call when nothing is up.
    fn teardown(&self) {
        let _ = run("nmcli", &["connection", "down", NM_CON_NAME]);
        let _ = run("nmcli", &["connection", "delete", NM_CON_NAME]);
        let _ = run("nmcli", &["device", "set", &self.ap_iface, "managed", "no"]);
        if let Err(e) = self.delete_vif() {
            debug!("NmSoftAp: vif delete on teardown: {e}");
        }
    }
}

impl Drop for NmSoftAp {
    /// Last-resort backstop: if an AP is still up when the `NmSoftAp` is dropped
    /// without [`SoftAp::stop`] having run (a refactor hazard, or the actor/handler
    /// Drop chain not completing), tear it down so a rogue SoftAP can't outlive us.
    /// Idempotent with `stop()` (the state is taken first), so a normal stop→drop
    /// does no duplicate work.
    fn drop(&mut self) {
        if self.state.lock().unwrap().take().is_some() {
            warn!("NmSoftAp: dropped with SoftAP still up — tearing down (backstop)");
            self.teardown();
        }
    }
}

impl SoftAp for NmSoftAp {
    fn start(&self, _service_id: &str) -> Option<HotspotCreds> {
        // Detect the STA's current frequency so the AP can be pinned co-channel. A
        // single-radio chip (the MT7925 this targets) can only run an AP on the
        // STA's channel, so a *guessed* channel risks bringing the AP up on the
        // wrong one — which fails activation or drags the STA's real association off
        // its channel. On detection failure we therefore bail (→ the offer policy
        // falls back to WIFI_LAN), never guess.
        let freq = match detect_sta_freq(&self.sta_iface) {
            Some(f) => f,
            None => {
                warn!(
                    "NmSoftAp: could not read STA freq for {}; not guessing a channel — \
                     falling back to WIFI_LAN",
                    self.sta_iface
                );
                return None;
            }
        };
        let channel = freq_to_channel(freq)?;
        let band = if freq >= 5000 { "a" } else { "bg" };

        // Free any stale `beamish-hotspot` connection from a crashed prior run BEFORE
        // touching the vif, so NM isn't managing an active connection on the iface we
        // delete (which can wedge `iw del` / leave NM inconsistent).
        let _ = run("nmcli", &["connection", "down", NM_CON_NAME]);
        let _ = run("nmcli", &["connection", "delete", NM_CON_NAME]);

        // Create the privileged vif.
        if let Err(e) = self.create_vif() {
            warn!("NmSoftAp: vif creation failed: {e}");
            return None;
        }

        // Generate transient SSID + WPA2 PSK.
        let ssid = format!("Beamish-{}", rand_hex(2));
        let psk = rand_hex(8); // 16 hex chars, within the 8..=63 WPA-PSK bound

        let chan = channel.to_string();
        let steps: Result<(), String> = (|| {
            run(
                "nmcli",
                &["device", "set", &self.ap_iface, "managed", "yes"],
            )?;
            run(
                "nmcli",
                &[
                    "connection",
                    "add",
                    "type",
                    "wifi",
                    "con-name",
                    NM_CON_NAME,
                    "ifname",
                    &self.ap_iface,
                    "autoconnect",
                    "no",
                    "ssid",
                    &ssid,
                    "802-11-wireless.mode",
                    "ap",
                    "802-11-wireless.band",
                    band,
                    "802-11-wireless.channel",
                    &chan,
                    "wifi-sec.key-mgmt",
                    "wpa-psk",
                    "wifi-sec.psk",
                    &psk,
                    "ipv4.method",
                    "shared",
                ],
            )?;
            // -w bounds activation so a SoftAP that can't come up fails in ~20s
            // (and the offer policy can fall back) instead of nmcli's 90s default.
            run("nmcli", &["-w", "20", "connection", "up", NM_CON_NAME])?;
            Ok(())
        })();
        if let Err(e) = steps {
            warn!("NmSoftAp: NM AP bring-up failed: {e}; tearing down");
            let _ = run("nmcli", &["connection", "delete", NM_CON_NAME]);
            let _ = self.delete_vif();
            return None;
        }

        // The actual gateway NM assigned (10.42.0.1 for the first shared conn).
        let gateway = detect_iface_ipv4(&self.ap_iface).unwrap_or(SHARED_GATEWAY);
        *self.state.lock().unwrap() = Some(ApState { ssid: ssid.clone() });
        info!(
            "NmSoftAp: SoftAP up — ssid={ssid} band={band} channel={channel} freq={freq} gateway={gateway}"
        );
        Some(HotspotCreds {
            ssid,
            password: psk,
            frequency: freq as i32,
            gateway,
            bind_ip: gateway,
        })
    }

    fn stop(&self, _service_id: &str) {
        match self.state.lock().unwrap().take() {
            Some(state) => info!("NmSoftAp: tearing down SoftAP ssid={}", state.ssid),
            None => debug!("NmSoftAp: stop with no active AP (ignored)"),
        }
        self.teardown();
        info!("NmSoftAp: SoftAP torn down");
    }

    fn connect_as_sta(&self, _creds: &HotspotCreds) -> Option<()> {
        // Responder side (joining someone else's AP). beamish is the initiator on
        // the receive path, so this is never called there. A future send-side path
        // would implement it (nmcli device wifi connect …).
        warn!("NmSoftAp: connect_as_sta is unimplemented (initiator-only path)");
        None
    }

    fn is_connected_to_hotspot(&self) -> bool {
        false
    }
}

// --- helpers ---------------------------------------------------------------

/// Run `cmd args…`, returning trimmed stdout on success or an error string
/// (including stderr) on non-zero exit / spawn failure.
fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    debug!("NmSoftAp: $ {cmd} {}", args.join(" "));
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {cmd} failed: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "{cmd} {} exited {:?}: {}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// First Wi-Fi device reported `connected` by `nmcli -t -f DEVICE,TYPE,STATE device`.
fn detect_connected_wifi_iface() -> Option<String> {
    let out = run("nmcli", &["-t", "-f", "DEVICE,TYPE,STATE", "device"]).ok()?;
    for line in out.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[1] == "wifi" && f[2] == "connected" {
            return Some(f[0].to_string());
        }
    }
    warn!("NmSoftAp: no connected wifi device found");
    None
}

/// The STA's current operating frequency (MHz), parsed from `iw dev <sta> link`.
fn detect_sta_freq(sta: &str) -> Option<u32> {
    parse_freq_mhz(&run("iw", &["dev", sta, "link"]).ok()?)
}

/// Parse the operating frequency (MHz) from `iw dev <sta> link` output. iw prints
/// the freq as a bare integer (`freq: 5745`) on older versions and a float
/// (`freq: 5745.0`) on newer ones, so take the integer MHz part of whichever form.
fn parse_freq_mhz(iw_link: &str) -> Option<u32> {
    for line in iw_link.lines() {
        if let Some(rest) = line.trim().strip_prefix("freq:") {
            let tok = rest.split_whitespace().next()?;
            return tok.split('.').next()?.parse().ok();
        }
    }
    None
}

/// Convert a Wi-Fi frequency (MHz) to its channel number.
fn freq_to_channel(freq: u32) -> Option<u32> {
    match freq {
        2412..=2472 => Some((freq - 2407) / 5),
        2484 => Some(14),
        5000..=5895 => Some((freq - 5000) / 5),
        _ => {
            warn!("NmSoftAp: unsupported AP frequency {freq} MHz");
            None
        }
    }
}

/// The first IPv4 address on `iface`, parsed from `ip -4 addr show <iface>`.
fn detect_iface_ipv4(iface: &str) -> Option<Ipv4Addr> {
    let out = run("ip", &["-4", "addr", "show", iface]).ok()?;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(cidr) = rest.split_whitespace().next() {
                if let Some(addr) = cidr.split('/').next() {
                    if let Ok(ip) = addr.parse() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// `n` random bytes, lowercase-hex encoded (length `2*n`).
fn rand_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freq_channel_mapping() {
        assert_eq!(freq_to_channel(5745), Some(149)); // 5GHz ch149 (our STA)
        assert_eq!(freq_to_channel(2412), Some(1)); // 2.4GHz ch1
        assert_eq!(freq_to_channel(2437), Some(6)); // 2.4GHz ch6
        assert_eq!(freq_to_channel(2484), Some(14)); // ch14
        assert_eq!(freq_to_channel(5180), Some(36)); // 5GHz ch36
        assert_eq!(freq_to_channel(1234), None); // out of band
    }

    #[test]
    fn rand_hex_length_and_charset() {
        let s = rand_hex(8);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_freq_handles_int_and_float() {
        // Newer iw prints a float (observed on the MT7925 dev box); older iw an int.
        let float_form = "Connected to aa:bb\n\tSSID: Barnabas\n\tfreq: 5745.0\n\tRX: 1";
        let int_form = "Connected to aa:bb\n\tSSID: Barnabas\n\tfreq: 5180\n";
        assert_eq!(parse_freq_mhz(float_form), Some(5745));
        assert_eq!(parse_freq_mhz(int_form), Some(5180));
        assert_eq!(parse_freq_mhz("Not connected."), None);
    }
}
