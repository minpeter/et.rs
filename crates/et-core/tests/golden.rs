#![forbid(unsafe_code)]

//! Golden compatibility test: every value is the exact byte output of the
//! pinned upstream C++ implementation (`/tmp/et-fixture-oracle/gen.cpp` linked
//! against the real `CryptoHandler.cpp` + protobufs). These are the source of
//! truth for wire parity; the Rust implementation must reproduce them exactly.

use et_core::crypto::{CryptoHandler, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN};
use et_core::framing::{frame_be_u32, frame_native_i64};
use et_core::packet::Packet;
use std::collections::HashMap;

fn fixtures() -> HashMap<String, Vec<u8>> {
    let raw = include_str!("../../../fixtures/wire.json");
    let map: HashMap<String, String> = serde_json::from_str(raw).unwrap();
    map.into_iter()
        .map(|(k, v)| (k, hex::decode(&v).unwrap()))
        .collect()
}

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn key() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    let bytes = hex::decode(KEY_HEX).unwrap();
    k.copy_from_slice(&bytes);
    k
}

#[test]
fn crypto_dir0_hello_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_CLIENT_TO_SERVER);
    let out = enc.encrypt(b"hello").unwrap();
    assert_eq!(
        out,
        *f.get("crypto_dir0_msg_hello").unwrap(),
        "client->server nonce scheme diverges from upstream"
    );
}

#[test]
fn crypto_dir1_hello_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_SERVER_TO_CLIENT);
    let out = enc.encrypt(b"hello").unwrap();
    assert_eq!(out, *f.get("crypto_dir1_msg_hello").unwrap());
}

#[test]
fn crypto_dir0_empty_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_CLIENT_TO_SERVER);
    let out = enc.encrypt(b"").unwrap();
    assert_eq!(out, *f.get("crypto_dir0_empty").unwrap());
}

#[test]
fn crypto_dir0_twoheader_body_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_CLIENT_TO_SERVER);
    let mut msg = Vec::new();
    msg.push(0);
    msg.push(0);
    msg.extend_from_slice(b"body");
    let out = enc.encrypt(&msg).unwrap();
    assert_eq!(out, *f.get("crypto_dir0_twoheader_body").unwrap());
}

#[test]
fn crypto_nonce_sequence_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_CLIENT_TO_SERVER);
    for (i, key) in [
        "crypto_dir0_seq0_x",
        "crypto_dir0_seq1_x",
        "crypto_dir0_seq2_x",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            enc.encrypt(b"x").unwrap(),
            *f.get(*key).unwrap(),
            "nonce step {} mismatch",
            i
        );
    }
}

#[test]
fn crypto_dir1_sequence_matches_oracle() {
    let f = fixtures();
    let mut enc = CryptoHandler::new(&key(), DIR_SERVER_TO_CLIENT);
    assert_eq!(
        enc.encrypt(b"x").unwrap(),
        *f.get("crypto_dir1_seq0_x").unwrap()
    );
    assert_eq!(
        enc.encrypt(b"x").unwrap(),
        *f.get("crypto_dir1_seq1_x").unwrap()
    );
}

#[test]
fn packet_unencrypted_matches_oracle() {
    let f = fixtures();
    let p = Packet::new(0, b"hello".to_vec());
    assert_eq!(
        p.serialize(),
        *f.get("packet_unencrypted_h0_hello").unwrap()
    );
}

#[test]
fn packet_encrypted_flag_and_header_matches_oracle() {
    let f = fixtures();
    let p = Packet::raw(true, 5, Vec::new());
    assert_eq!(p.serialize(), *f.get("packet_encrypted_h5_empty").unwrap());
    let p = Packet::raw(true, 254, b"k".to_vec());
    assert_eq!(p.serialize(), *f.get("packet_encrypted_h254_k").unwrap());
}

#[test]
fn native_i64_frame_matches_oracle() {
    let f = fixtures();
    let seq42 = f.get("proto_sequenceheader_42").unwrap();
    assert_eq!(
        frame_native_i64(seq42),
        *f.get("sockethandler_nativei64_seq42").unwrap()
    );
}

#[test]
fn be_u32_frame_matches_oracle() {
    let f = fixtures();
    let packet = Packet::new(1, b"hi".to_vec()).serialize();
    assert_eq!(frame_be_u32(&packet), [0, 0, 0, 4, 0, 1, b'h', b'i']);
    let _ = f;
}
