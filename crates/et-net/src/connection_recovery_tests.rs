use et_core::backed_writer::{MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS};

use super::validate_catchup_encoding;

#[test]
fn catchup_wire_rejects_empty_and_excessive_entries() {
    assert!(validate_catchup_encoding(&[0x0a, 0]).is_err());
    let limit = MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS;
    let mut excessive = Vec::with_capacity((limit + 1) * 3);
    for _ in 0..=limit {
        excessive.extend_from_slice(&[0x0a, 1, 0]);
    }
    assert!(validate_catchup_encoding(&excessive).is_err());
}

#[test]
fn catchup_wire_rejects_overflowing_varints() {
    let mut encoded = vec![0x0a];
    encoded.extend_from_slice(&[0xff; 10]);
    assert!(validate_catchup_encoding(&encoded).is_err());
}
