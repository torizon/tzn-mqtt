use std::{fmt::Debug, time::Duration};

use rac_dbus::RacProxy;
use serde::Serialize;
use tokio::sync::mpsc;
use zbus::Connection;

use crate::{dbus::ServiceEvent, Result};

mod rac_dbus {
    use zbus::proxy;

    #[proxy(
        interface = "io.torizon.Rac1",
        default_service = "io.torizon.Rac1",
        default_path = "/io/torizon/Rac1",
        gen_blocking = false
    )]
    pub trait Rac {
        fn poll_ras_now(&self, args_json: &str) -> zbus::Result<()>;
    }
}

async fn handle_event<T: Serialize + Debug>(
    conn: &Connection,
    event: &ServiceEvent<T>,
) -> Result<()> {
    log::debug!("Handling event: {:?}", event);

    if event.command == "PollRasNow" {
        log::debug!("sending poll_ras_now to RAC");
        let proxy = RacProxy::new(&conn).await?;
        let args_json = serde_json::to_string(&event.args)?;

        match proxy.poll_ras_now(&args_json).await {
            Ok(()) => log::info!("sent poll_ras_now request to rac"),
            Err(zbus::Error::MethodError(name, desc, _msg))
                if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown" =>
            {
                log::warn!("rac not available on dbus. Is rac running? {desc:?}")
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

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

        log::error!("rac channel closed");
    });

    Ok(tx)
}
