# feat(core): advertise as a discoverable Quick Share receiver over BLE (Linux)

## Problem

On the current **unified Quick Share** (Pixel 9, recent Samsung, post-2024 GMS), Android **cannot discover an rquickshare/Packet receiver**. You can send *from* Linux, but the phone never lists the Linux machine as a target to send *to*.

Root cause: rquickshare advertises receivers over **mDNS only**, but modern Quick Share **does not browse mDNS for receivers**. It discovers them via a **BLE advertisement** and only then connects over the negotiated medium. With no BLE receiver advertisement, the phone has nothing to surface. (This is the same limitation NearDrop documents on macOS — except macOS *can't* send these adverts, while Linux/BlueZ can.)

Verified by sniffing a Pixel 9 Pro XL in receive mode (`btmon`) and cross-checked against Google's open source (`github.com/google/nearby`, `connections/implementation/ble_advertisement.*`) and grishka's `NearDrop/PROTOCOL.md`.

## Change

New `BleConnectionsAdvertiser` (`core_lib/src/hdl/blea2.rs`), spawned from `RQS::run()` on Linux when the `experimental` feature is on. It emits a real **Nearby Connections `BleAdvertisement`** under service UUID **`0xFEF3`** (connectable + LE extended), carrying **this receiver's `endpoint_id`** so the phone correlates the BLE-discovered endpoint with our existing mDNS/WiFi-LAN endpoint and connects to the existing TCP server. The receiver, UKEY2 handshake, consent flow and file handling are all unchanged — this is purely the missing *discovery* piece.

Design notes:
- **WiFi-LAN-only v1:** we zero the `BLUETOOTH_MAC` field and omit the L2CAP capability tail, so the phone connects over WiFi to the existing TCP receiver rather than a BLE L2CAP CoC (which we don't serve). Connecting over WiFi is also far faster.
- **Stable `endpoint_id`** derived from `/etc/machine-id` (random fallback) so app restarts don't leave ghost entries on the sender.
- Endpoint info is the standard Quick Share advertisement `[VER|VIS][SALT 2][METADATA_KEY 14][LEN][NAME]`; "Everyone" mode → plaintext name.

## Verified

End-to-end: Pixel 9 Pro XL → Linux, 5.2 MB photo received and saved to `~/Downloads`. Discovery → WiFi connect → UKEY2 (PIN) → consent → `ReceivingFiles` → `Finished`.

## Limitations / follow-ups

- **Linux/BlueZ only** (cfg-gated). macOS cannot emit these adverts.
- **Requires Bluetooth on** (BLE is the discovery trigger) and WiFi LAN with mDNS allowed for the transfer.
- **BT-only networks** would need a Nearby Connections **L2CAP CoC server** bridged into the medium-agnostic connection handler — left as future work.

## Files

- `core_lib/src/hdl/blea2.rs` (new) — the advertiser
- `core_lib/src/hdl/mod.rs` — module wiring (Linux + experimental)
- `core_lib/src/lib.rs` — stable endpoint_id; spawn advertiser in `run()`
- `core_lib/src/bin.rs` — headless `core_bin` auto-accepts incoming transfers (handy as a daemon)
