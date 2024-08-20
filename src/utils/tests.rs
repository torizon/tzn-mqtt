// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0


#[cfg(test)]
mod tests {
    use std::path::Path;
    use crate::utils::{load_cert, load_private_key, read_device_id, parse_payload};
    

    #[test]
    fn test_load_cert() {
        let cert_path = Path::new("src/utils/test_data/client.crt");
        let result = load_cert(cert_path);
        assert!(result.is_ok(), "Failed to load certificate: {:?}", result.err());
    
        let cert = result.expect("Valid certificate");
        assert!(cert.len() > 0, "Certificate data should not be empty");
    }

    #[test]
    fn test_load_private_key() {
        let key_path = Path::new("src/utils/test_data/client.key");
        let result = load_private_key(key_path);
        assert!(result.is_ok(), "Failed to load private key: {:?}", result.err());
    }

    #[test]
    fn test_read_device_id() {
        let cert_path = Path::new("src/utils/test_data/client.crt");
        let cert = load_cert(cert_path).expect("Failed to load cert");
        let result = read_device_id(&cert);
        assert!(result.is_ok(), "Failed to read device id: {:?}", result.err());

        let device_id = result.expect("Valid device ID");
        assert!(!device_id.is_empty(), "Device ID should not be empty");
    }

    #[test]
    fn test_parse_payload() {
        let payload = br#"{"command": "test", "args": {"key": "value"}}"#;
        let result = parse_payload(payload);
        assert!(result.is_ok(), "Failed to parse payload: {:?}", result.err());

        let (command, args) = result.expect("Valid command and args");
        assert_eq!(command, "test");
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn test_parse_payload_missing_args() {
        let payload = br#"{"command": "test"}"#;
        let result = parse_payload(payload);
        assert!(result.is_err(), "Expected error for missing `args`, got: {:?}", result);
    }

    #[test]
    fn test_parse_payload_missing_command() {
        let payload = br#"{"args": {"key": "value"}}"#;
        let result = parse_payload(payload);
        assert!(result.is_err(), "Expected error for missing `command`, got: {:?}", result);
    }
}
