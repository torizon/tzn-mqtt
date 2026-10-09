use std::{fmt::Debug, time::Duration};

use aktualizr_dbus::AktualizrProxy;
use serde::Serialize;
use tokio::sync::mpsc;
use zbus::Connection;

use crate::{dbus::ServiceEvent, Result};

mod aktualizr_dbus {
    use zbus::proxy;

    #[proxy(
        interface = "org.uptane.Aktualizr",
        default_service = "org.uptane.Aktualizr",
        default_path = "/org/uptane/aktualizr",
        gen_blocking = false
    )]
    pub trait Aktualizr {
        /// Cancel method
        fn cancel(&self) -> zbus::Result<()>;

        /// CheckForUpdates method
        fn check_for_updates(&self) -> zbus::Result<()>;

        /// Consent method
        fn consent(&self, arg_1: bool, arg_2: &str) -> zbus::Result<()>;

        /// OfflineUpdate method
        fn offline_update(&self, arg_1: &str) -> zbus::Result<()>;

        /// ConsentRequired property
        #[zbus(property)]
        fn consent_required(&self) -> zbus::Result<String>;

        /// InstallUpdatesAutomatically property
        #[zbus(property)]
        fn install_updates_automatically(&self) -> zbus::Result<i32>;

        #[zbus(property)]
        fn set_install_updates_automatically(&self, value: i32) -> zbus::Result<()>;
    }
}

async fn handle_event<T: Serialize + Debug>(
    conn: &Connection,
    event: &ServiceEvent<T>,
) -> Result<()> {
    log::debug!("Handling event: {:?}", event);

    if event.command == "CheckForUpdates" {
        log::debug!("sending check_for_updates to aktualizr args={:?}", event.args);
        let proxy = AktualizrProxy::new(&conn).await?;
        match proxy.check_for_updates().await {
            Ok(()) => log::info!("sent check_for_updates request to aktualizr"),
            Err(zbus::Error::MethodError(name, desc, _msg))
                if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown" =>
            {
                log::warn!("aktualizr not available on dbus. Is aktualizr running? {desc:?}")
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

// Listen to events and decide whether to translate them to aktualizr commands or not.
// If the command should be translated to aktualizr dbus, send it to dbus
pub async fn start<T: Sized + Serialize + Sync + Debug + Send + 'static>(
) -> Result<mpsc::Sender<ServiceEvent<T>>> {
    let (tx, mut rx) = mpsc::channel(10);

    let connection = Connection::system().await?;

    tokio::task::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(err) = handle_event(&connection, &event).await {
                log::error!("Could not handle event: {:#?}", err);
                log::debug!("waiting 3 seconds");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }

        log::error!("aktualizr channel closed");
    });

    Ok(tx)
}
