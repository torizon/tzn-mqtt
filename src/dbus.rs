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
        debug!("Handling event: {:?}", event);
        
        let args = serde_json::to_string(&event.args)?;
        debug!("Serialized args: {}", args);
        
        match TznService::tzn_message_sig(ctx, &event.command, &args).await {
            Ok(()) => debug!("Event sent successfully: command={}, args={}", event.command, args),
            Err(err) => {
                error!("Failed to send event: command={}, args={}, error={:?}", event.command, args, err);
                return Err(err.into());
            }
        }

        Ok(())
    }

    async fn dbus_connect() -> Result<zbus::InterfaceRef<TznService>> {
        info!("Attempting to connect to DBus");

        let tzn_service = TznService {};

        match zbus::connection::Builder::session()?
            .name("io.torizon.TznService")?
            .serve_at("/io/torizon/TznService", tzn_service)?
            .build()
            .await
        {
            Ok(connection) => {
                info!("Connected to DBus successfully");
                
                match connection.object_server().interface::<_, TznService>("/io/torizon/TznService").await {
                    Ok(iface_ref) => {
                        debug!("Interface reference obtained");
                        Ok(iface_ref)
                    }
                    Err(err) => {
                        error!("Failed to get interface reference: {:?}", err);
                        Err(err.into())
                    }
                }
            }
            Err(err) => {
                error!("Failed to connect to DBus: {:?}", err);
                Err(err.into())
            }
        }
    }

    pub async fn start<T: Sized + Serialize + Sync + Debug + Send + 'static>(
    ) -> Result<mpsc::Sender<ServiceEvent<T>>> {
        info!("Starting the service");

        let (tx, mut rx) = mpsc::channel(10);

        tokio::task::spawn(async move {
            loop {
                match dbus_connect().await {
                    Err(err) => {
                        error!("Could not connect to DBus: {:?}", err);
                    }
                    Ok(iface) => loop {
                        match rx.recv().await {
                            Some(event) => {
                                let ctx = iface.signal_context();

                                if let Err(err) = handle_event(&event, ctx).await {
                                    error!("Could not send event to DBus: {:?}", err);
                                    break;
                                }
                            }
                            None => {
                                error!("Channel closed");
                                break;
                            }
                        }
                    },
                }

                info!("Retrying in 3 seconds...");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        Ok(tx)
    }
}
