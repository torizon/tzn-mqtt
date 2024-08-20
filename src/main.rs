// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

use std::{io::ErrorKind, path::Path, time::Duration};

use dbus::ServiceEvent;
use log::*;

use eyre::{Context, OptionExt};
use rumqttc::{
    tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer},
    ConnectionError,
};
use tokio::sync::mpsc::Sender;

mod dbus;

type Result<T> = std::result::Result<T, eyre::Report>;

// blocking
fn load_cert<P: AsRef<Path>>(filename: P) -> Result<CertificateDer<'static>> {
    let certfile =
        std::fs::File::open(&filename).context(format!("opening {:?}", filename.as_ref()))?;
    let mut reader = std::io::BufReader::new(&certfile);
    let mut all_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader).flatten().collect();

    if all_certs.len() != 1 {
        eyre::bail!(
            "invalid number of certificates in {:?}, expected 1 got {:?}",
            filename.as_ref(),
            all_certs.len()
        );
    }

    #[allow(clippy::unwrap_used)] // length checked
    Ok(all_certs.pop().unwrap())
}

// blocking
fn load_private_key<P: AsRef<Path>>(filename: P) -> Result<PrivateKeyDer<'static>> {
    let keyfile =
        std::fs::File::open(&filename).context(format!("read {:?}", filename.as_ref()))?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => {}
        }
    }

    eyre::bail!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename.as_ref()
    );
}

fn read_device_id(cert: &CertificateDer) -> Result<String> {
    use x509_parser::prelude::*;

    let (_, res) = X509Certificate::from_der(cert)?;

    let common_name = res
        .subject
        .iter_common_name()
        .flat_map(|c| c.as_str())
        .next();

    Ok(common_name
        .ok_or(eyre::eyre!("Could not extract uuid from certificate CN"))?
        .to_owned())
}

fn parse_payload(payload: &[u8]) -> Result<(String, serde_json::Value)> {
    let mut payload_json: serde_json::Value = serde_json::from_slice(payload)?;

    let args_json = payload_json
        .pointer_mut("/args")
        .ok_or_eyre("message payload did not include `args`")?
        .take();

    let command = payload_json
        .pointer("/command")
        .and_then(|s| s.as_str().map(|s| s.to_owned()))
        .ok_or_eyre("message payload did not include `command`")?;

    Ok((command, args_json))
}

async fn run() -> Result<()> {
    let mqtt_hostname = std::env::var("TZN_MQTT_HOST").unwrap_or("mqtt.dev.torizon.io".to_owned());
    let mqtt_port = std::env::var("TZN_MQTT_PORT").unwrap_or("8883".to_owned());
    
    let (device_id, client_config) = if cfg!(feature = "test_mode") {
        ("tzntestmqtt".to_owned(), None)
    } else {
        let client_cert_path = std::env::var("TZN_CLIENT_CERT").unwrap_or("/var/sota/import/client.pem".to_owned());
        let client_key_path = std::env::var("TZN_CLIENT_KEY").unwrap_or("/var/sota/import/pkey.pem".to_owned());
    
        let root_cert_store = rumqttc::tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
    
        let client_cert = load_cert(&client_cert_path)?;
        let client_key = load_private_key(&client_key_path)?;
    
        let device_id = read_device_id(&client_cert)?;
    
        let client_config = rumqttc::tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(vec![client_cert], client_key)?;
    
        (device_id, Some(client_config))
    };
    
    info!("connecting to {device_id}@{mqtt_hostname}:{mqtt_port}");
    
    let mut mqttoptions = rumqttc::MqttOptions::new(
        &device_id,
        mqtt_hostname,
        mqtt_port.parse().context("could not parse mqtt port number")?,
    );
    
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(5));
    
    if let Some(client_config) = client_config {
        mqttoptions.set_transport(rumqttc::Transport::tls_with_config(
            rumqttc::TlsConfiguration::Rustls(std::sync::Arc::new(client_config)),
        ));
    }

    let (mqtt_client, mut eventloop) = rumqttc::AsyncClient::new(mqttoptions, 10);

    mqtt_client
        .subscribe(
            format!("ota/commands/device/{device_id}/#"),
            rumqttc::QoS::AtLeastOnce,
        )
        .await?;

    let mut connecting = true;
    let mut connect_retry = 3;

    let dbus_server_tx: Sender<ServiceEvent<serde_json::Value>> = dbus::server::start().await?;

    loop {
        // The first time we try to connect we retry a few times because if the device was
        // never provisioned before, the server will reset the connection and the next connection
        // attempt will succeed
        let mqtt_event = match eventloop.poll().await {
            Ok(event) => {
                if connecting {
                    connecting = false;
                    info!("connected to mqtt");
                }

                event
            }
            Err(ConnectionError::Io(err))
                if err.kind() == ErrorKind::ConnectionAborted
                    && connecting
                    && connect_retry > 0 =>
            {
                connect_retry -= 1;
                warn!("server closed the connection, retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
            Err(err) => return Err(err.into()),
        };

        match mqtt_event {
            rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) => {
                info!("received message: {:?}", publish);

                match parse_payload(&publish.payload) {
                    Ok((command, args)) => {
                        info!("command={}, args={}", command, args);

                        if let Err(err) = dbus_server_tx.try_send(ServiceEvent { command, args }) {
                            error!("could not send command to dbus: {err:?}");
                        }
                    }
                    Err(err) => error!("could not parse payload as json: {:?}", err),
                }
            }
            msg => debug!("received from mqtt: {:?}", msg),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "tzn_mqtt=info");
    }

    pretty_env_logger::init_timed();

    color_eyre::install().expect("could no initialize color_eyre");

    run().await.expect("could not run mqtt subscribe loop");
}
