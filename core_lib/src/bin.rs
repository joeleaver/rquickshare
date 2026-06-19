#[macro_use]
extern crate log;

use rqs_lib::channel::{ChannelAction, ChannelDirection, ChannelMessage};
use rqs_lib::{State, RQS};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            "INFO,mdns_sd=ERROR,polling=ERROR,neli=ERROR,bluez_async=ERROR",
        );
    }
    tracing_subscriber::fmt::init();

    // Receive-only: run() advertises via mDNS + our 0xFEF3 BLE receiver advert
    // and listens on TCP. We deliberately do NOT call discovery() (that's for
    // SENDING and starts the legacy beacon).
    let mut rqs = RQS::default();
    rqs.run().await?;

    // Headless auto-accept: when an inbound transfer asks for consent, accept it.
    let mut rx = rqs.message_sender.subscribe();
    let tx = rqs.message_sender.clone();
    tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if msg.direction != ChannelDirection::LibToFront {
                continue;
            }
            if let Some(state) = &msg.state {
                info!("[{}] state: {:?}", msg.id, state);
                if *state == State::WaitingForUserConsent {
                    info!("[{}] auto-accepting transfer", msg.id);
                    let _ = tx.send(ChannelMessage {
                        id: msg.id.clone(),
                        direction: ChannelDirection::FrontToLib,
                        action: Some(ChannelAction::AcceptTransfer),
                        ..Default::default()
                    });
                }
            }
        }
    });

    info!("rquickshare headless receiver ready. Ctrl-C to stop.");
    let _ = tokio::signal::ctrl_c().await;
    info!("Stopping service.");
    rqs.stop().await;

    Ok(())
}
