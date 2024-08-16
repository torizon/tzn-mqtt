use color_eyre::Result;
use log::*;
use zbus::{proxy, Connection};
use tokio;
use std::time::Duration;
use futures_util::stream::StreamExt;

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
        "received signal in dbus. command={} args={}",
        args.command, json_args
    );

    Ok(())
}

async fn dbus_connect() -> Result<TznMessageSigStream<'static>> {
    let connection = Connection::session().await?;
    let dbus_proxy = TznServiceProxy::new(&connection).await?;
    let events = dbus_proxy.receive_tzn_message_sig().await?;
    Ok(events)
}

pub async fn start() -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            match dbus_connect().await {
                Ok(mut events) => {
                    while let Some(msg) = events.next().await {
                        if let Err(err) = handle_event(&msg) {
                            info!("could not handle {:?}: {:?}", msg, err);
                        }
                    }

                    error!("event stream/dbus finished unexpectedly");
                }
                Err(err) => warn!("could not connect to dbus: {:?}", err),
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?; // or eyre::install() if you're using eyre
    start().await?;
    Ok(())
}
