// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use rustls_pemfile;
use eyre::{Context, Result, OptionExt};
use x509_parser::prelude::*;
use serde_json;
use crate::CertificateDer;
use crate::PrivateKeyDer;

// blocking
pub fn load_cert<P: AsRef<Path>>(filename: P) -> Result<CertificateDer<'static>> {
    let certfile =
        File::open(&filename).context(format!("opening {:?}", filename.as_ref()))?;
    let mut reader = BufReader::new(&certfile);
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
pub fn load_private_key<P: AsRef<Path>>(filename: P) -> Result<PrivateKeyDer<'static>> {
    let keyfile =
        File::open(&filename).context(format!("read {:?}", filename.as_ref()))?;
    let mut reader = BufReader::new(keyfile);

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

pub fn read_device_id(cert: &CertificateDer) -> Result<String> {
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

pub fn parse_payload(payload: &[u8]) -> Result<(String, serde_json::Value)> {
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
