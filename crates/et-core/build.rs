#![forbid(unsafe_code)]

use std::io::Result;

fn main() -> Result<()> {
    let mut cfg = prost_build::Config::new();
    cfg.out_dir(std::env::var("OUT_DIR").unwrap());
    cfg.compile_protos(&["proto/ET.proto", "proto/ETerminal.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/ET.proto");
    println!("cargo:rerun-if-changed=proto/ETerminal.proto");
    Ok(())
}
