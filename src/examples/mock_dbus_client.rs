use color_eyre::Result;
use log::*;
use zbus::{proxy, Connection};
use tokio;
use std::time::Duration;
use futures_util::stream::StreamExt;
use serde_json;

#[proxy(
    interface = "io.torizon.TznService1",
    default_service = "io.torizon.TznService",
    default_path = "/io/torizon/TznService"
)]
trait TznService {
    #[zbus(signal)]
    async fn tzn_message_sig(command: &str, arg_json: &str) -> zbus::Result<()>;
}

fn handle_event(msg: &TznMessageSig) -> Result<()> {
    let args: TznMessageSigArgs = msg.args()?;
    let json_args: serde_json::Value = serde_json::from_str(args.arg_json)?;

    info!(
        "Received signal from DBus. Command: '{}', Arguments: {}",
        args.command, json_args
    );

    Ok(())
}

async fn dbus_connect() -> Result<TznMessageSigStream<'static>> {
    info!("Connecting to DBus...");
    let connection = Connection::session().await?;
    info!("Connected to DBus");

    let dbus_proxy = TznServiceProxy::new(&connection).await?;
    info!("DBus proxy created");

    let events = dbus_proxy.receive_tzn_message_sig().await?;
    info!("Listening for events...");

    Ok(events)
}

pub async fn start() -> Result<()> {
    info!("Starting background task...");
    tokio::task::spawn(async move {
        loop {
            match dbus_connect().await {
                Ok(mut events) => {
                    info!("Event stream started successfully");

                    while let Some(msg) = events.next().await {
                        if let Err(err) = handle_event(&msg) {
                            error!("Failed to handle message: {:?}. Error: {:?}", msg, err);
                        }
                    }

                    error!("Event stream/DBus finished unexpectedly");
                }
                Err(err) => {
                    error!("Failed to connect to DBus: {:?}", err);
                }
            }

            info!("Retrying connection in 3 seconds...");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "trace");
    }

    pretty_env_logger::init_timed();
    color_eyre::install()?;

    info!("Application starting...");
    start().await?;

    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl+C, shutting down...");

    Ok(())
}
