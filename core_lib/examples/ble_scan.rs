//! Headless probe for Phase 1 of PC->phone BLE send-discovery.
//!
//! Scans for nearby Quick Share receivers (service 0xFE2C) and decodes the
//! Nearby Share BLE advertisement to pull out the device name (present only
//! when the phone is "visible to everyone"). Logs the raw bytes so we can
//! validate the format against a real phone/GMS version.
//!
//!   cargo run --example ble_scan --features experimental
//!
//! Then on the phone: Quick Share -> "visible to everyone" (or open the
//! receive screen). The phone should print as a DISCOVERED PHONE line.

use std::collections::HashMap;
use std::io::Write;

use btleplug::api::{Central, CentralEvent, Manager as _, ScanFilter};
use btleplug::platform::Manager;
use futures::stream::StreamExt;
use uuid::{uuid, Uuid};

const SERVICE_UUID_SHARING: Uuid = uuid!("0000fe2c-0000-1000-8000-00805f9b34fb");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("")
}

/// println + flush so detached/file-redirected runs don't lose buffered output.
fn out(s: String) {
    println!("{s}");
    let _ = std::io::stdout().flush();
}

/// Nearby Connections "fast advertisement" wrapper:
/// `[VER(3)|SOCKET_VER(3)|FAST_FLAG(1)|RESERVED(1)][DATA_SIZE][DATA]...`
/// Returns the inner DATA (the Nearby Share endpoint_info).
fn parse_fast_adv_data(sd: &[u8]) -> Option<&[u8]> {
    if sd.len() < 2 {
        return None;
    }
    let data_size = sd[1] as usize;
    if data_size == 0 || sd.len() < 2 + data_size {
        return None;
    }
    Some(&sd[2..2 + data_size])
}

/// Nearby Share Advertisement endpoint_info:
/// `[VER(3)|HASNAME(bit4:0=has)|TYPE(3)|R][SALT(2)][KEY(14)][LEN][NAME]...`
/// Returns (device_name, device_type) when it parses as visible-to-everyone.
fn parse_share_advert(ei: &[u8]) -> Option<(Option<String>, u8, u8)> {
    const MIN: usize = 1 + 2 + 14;
    if ei.len() < MIN {
        return None;
    }
    let b0 = ei[0];
    let version = (b0 >> 5) & 0x07;
    if version > 1 {
        return None;
    }
    let has_name = ((b0 >> 4) & 0x01) == 0;
    let device_type = (b0 >> 1) & 0x07;
    let mut i = MIN;
    let mut name = None;
    if has_name {
        if i >= ei.len() {
            return None;
        }
        let len = ei[i] as usize;
        i += 1;
        if len == 0 || i + len > ei.len() {
            return None;
        }
        // Device names are UTF-8; reject if it isn't (wrong offset/format).
        match std::str::from_utf8(&ei[i..i + len]) {
            Ok(s) => name = Some(s.to_string()),
            Err(_) => return None,
        }
    }
    Some((name, version, device_type))
}

/// Try the share advertisement both directly and behind the fast-adv wrapper.
fn decode(sd: &[u8]) -> Option<(Option<String>, u8, u8, &'static str)> {
    if let Some((n, v, t)) = parse_share_advert(sd) {
        return Some((n, v, t, "direct"));
    }
    if let Some(data) = parse_fast_adv_data(sd) {
        if let Some((n, v, t)) = parse_share_advert(data) {
            return Some((n, v, t, "fast-adv"));
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = Manager::new().await?;
    let central = manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or("no bluetooth adapter")?;

    out("scanning ALL BLE advertisements (no UUID filter)...".into());
    out("on the phone: Quick Share -> visible to everyone (or open the receive screen)".into());

    let secs: u64 = std::env::var("BLE_SCAN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    let mut events = central.events().await?;
    out("events() ok; starting scan...".into());
    // Empty filter = report everything, so we see exactly which service UUID the
    // phone advertises (not just 0xFE2C). Guarded so a wedged adapter bails.
    match tokio::time::timeout(
        std::time::Duration::from_secs(6),
        central.start_scan(ScanFilter::default()),
    )
    .await
    {
        Ok(Ok(())) => out("start_scan ok; listening...".into()),
        Ok(Err(e)) => {
            out(format!("start_scan error: {e}"));
            return Err(e.into());
        }
        Err(_) => {
            out("start_scan TIMED OUT (adapter wedged?); try: bluetoothctl power off/on".into());
            return Err("start_scan timed out".into());
        }
    }

    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut adv_count = 0u64;
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                out(format!("\nscan window ({secs}s) elapsed; stopping."));
                break;
            }
            ev = events.next() => {
                let Some(ev) = ev else { break };
                if let CentralEvent::ServiceDataAdvertisement { id, service_data } = ev {
                    let addr = format!("{id:?}");
                    // Log every service-data UUID this device advertises.
                    for (uuid, sd) in &service_data {
                        let short = format!("{uuid}");
                        let tag = if *uuid == SERVICE_UUID_SHARING { " <-- QUICKSHARE(fe2c)" } else { "" };
                        out(format!("[adv] {addr} svc={short}{tag} ({} bytes): {}", sd.len(), hex(sd)));
                    }
                    if let Some(sd) = service_data.get(&SERVICE_UUID_SHARING) {
                        match decode(sd) {
                            Some((name, version, dt, via)) => {
                                out(format!("      decode: via={via} version={version} device_type={dt} name={name:?}"));
                                if let Some(n) = name {
                                    if seen.insert(n.clone(), ()).is_none() {
                                        out(format!("  *** DISCOVERED PHONE: \"{n}\" (type {dt}) at {addr} ***"));
                                    }
                                }
                            }
                            None => out("      (fe2c present but could not decode as a share advertisement)".into()),
                        }
                    }
                    adv_count += 1;
                }
            }
        }
    }

    let _ = central.stop_scan().await;
    out(format!("done. {adv_count} service-data adverts seen, {} unique phone name(s).", seen.len()));
    Ok(())
}
