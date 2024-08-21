// Copyright 2024 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0


#[cfg(test)]
mod tests {
    use std::path::Path;
    use nix::unistd::Uid;
    use crate::utils::{load_cert, load_private_key, read_device_id, parse_payload, drop_privileges};
    

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

    #[test]
    fn test_drop_privileges_non_root() {
        // This test should only be run as a non-root user
        if nix::unistd::getuid().is_root() {
            panic!("This test should not be run as root");
        }

        let result = drop_privileges();
        assert!(result.is_ok(), "Expected Ok(()), got {:?}", result);
    }

    #[test]
    fn test_drop_privileges_root_user_simulation() {
        // Simulate root user environment by temporarily setting nix::unistd::setuid to return root
        let original_uid = nix::unistd::getuid();
        let root_uid = Uid::from_raw(0);
        let _ = nix::unistd::setuid(root_uid);

        let result = drop_privileges();

        let _ = nix::unistd::setuid(original_uid);

        match original_uid.is_root() {
            true => assert!(result.is_err(), "Expected an error, got {:?}", result),
            false => assert!(result.is_ok(), "Expected Ok(()), got {:?}", result),
        }
    }
}
