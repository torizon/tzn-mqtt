// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

#[derive(Debug)]
pub(crate) struct ServiceEvent<T: Debug> {
    pub command: String,
    pub args: T,
}

pub mod server {
    use std::fmt::Debug;

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

    pub async fn start<T: Sized + Serialize + Sync + Debug + Send + 'static>(
    ) -> Result<mpsc::Sender<ServiceEvent<T>>> {
    
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

        let (tx, mut rx) = mpsc::channel(10);

        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    event_o = rx.recv() => {
                        match event_o {
                            Some(event) => {
                                let ctx = iface_ref.signal_context();

                                if let Err(err) = handle_event(&event, ctx).await {
                                    error!("could not send event to dbus: {err:?}")
                                }
                            },
                            None => {
                                error!("channel closed");
                                break;
                            }
                        }
                    },
                }
            }
        });

        Ok(tx)
    }
}

// This is just an example of a mock client for our dbus server, for example,
// RAC or aktualizr could run something like this
pub mod client {
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

    pub async fn start() -> crate::Result<()> {
        let connection = Connection::session().await?;

        let dbus_proxy = TznServiceProxy::new(&connection).await?;

        let mut events = dbus_proxy.receive_tzn_message_sig().await?;

        tokio::task::spawn(async move {
            while let Some(msg) = events.next().await {
                if let Err(err) = handle_event(&msg) {
                    error!("could not handle {:?}: {:?}", msg, err);
                }
            }
            error!("event stream finished unexpectedly");
        });

        Ok(())
    }
}
