// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct ServiceEvent<T: Debug> {
    pub command: String,
    pub args: T,
}

pub mod server {
    use std::{fmt::Debug, time::Duration};

    use crate::Result;
    use log::*;
    use serde::ser::Serialize;
    use tokio::sync::mpsc;
    use zbus::object_server::SignalContext;

    use super::ServiceEvent;

    struct TznService {}

    #[zbus::interface(
        name = "io.torizon.TznService1",
        proxy(
            gen_blocking = false,
            default_path = "/io/torizon/TznService",
            default_service = "io.torizon.TznService",
        )
    )]
    impl TznService {
        #[zbus(signal)]
        async fn tzn_message_sig(
            signal_ctxt: &zbus::object_server::SignalContext<'_>,
            command: &str,
            args_json: &str,
        ) -> zbus::Result<()>;
    }

    async fn handle_event<T: Serialize + Debug>(
        event: &ServiceEvent<T>,
        ctx: &SignalContext<'_>,
    ) -> Result<()> {
        let args = serde_json::to_string(&event.args)?;
        TznService::tzn_message_sig(ctx, &event.command, &args).await?;

        Ok(())
    }

    async fn dbus_connect() -> Result<zbus::InterfaceRef<TznService>> {
        let tzn_service = TznService {};

        let connection = zbus::connection::Builder::session()?
            .name("io.torizon.TznService")?
            .serve_at("/io/torizon/TznService", tzn_service)?
            .build()
            .await?;

        let iface_ref = connection
            .object_server()
            .interface::<_, TznService>("/io/torizon/TznService")
            .await?;

        Ok(iface_ref)
    }

    pub async fn start<T: Sized + Serialize + Sync + Debug + Send + 'static>(
    ) -> Result<mpsc::Sender<ServiceEvent<T>>> {
        let (tx, mut rx) = mpsc::channel(10);

        tokio::task::spawn(async move {
            loop {
                match dbus_connect().await {
                    Err(err) => {
                        error!("could not connect to dbus: {:?}", err);
                    }
                    Ok(iface) => loop {
                        let event_o = rx.recv().await;
                        match event_o {
                            Some(event) => {
                                let ctx = iface.signal_context();

                                if let Err(err) = handle_event(&event, ctx).await {
                                    error!("could not send event to dbus: {err:?}");
                                    break;
                                }
                            }
                            None => {
                                error!("channel closed");
                                break;
                            }
                        }
                    },
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        Ok(tx)
    }
}

// This is just an example of a mock client for our dbus server, for example,
// RAC or aktualizr could run something like this
pub mod client {
    use std::time::Duration;

    use futures_util::stream::StreamExt;
    use log::*;
    use zbus::{proxy, Connection};

    #[proxy(
        interface = "io.torizon.TznService1",
        default_service = "io.torizon.TznService",
        default_path = "/io/torizon/TznService"
    )]
    trait TznService {
        #[zbus(signal)]
        async fn tzn_message_sig(command: &str, arg_json: &str) -> zbus::Result<()>;
    }

    fn handle_event(msg: &TznMessageSig) -> crate::Result<()> {
        let args: TznMessageSigArgs = msg.args()?;
        let json_args: serde_json::Value = serde_json::from_str(args.arg_json)?;

        info!(
            "received signal in dbus. command={} args={}",
            args.command, json_args
        );

        Ok(())
    }

    async fn dbus_connect() -> crate::Result<TznMessageSigStream<'static>> {
        let connection = Connection::session().await?;

        let dbus_proxy = TznServiceProxy::new(&connection).await?;

        let events = dbus_proxy.receive_tzn_message_sig().await?;

        Ok(events)
    }

    pub async fn start() -> crate::Result<()> {

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

}
