#![forbid(unsafe_code)]

//! Internal secure server-listener and local terminal registration foundation.
//!
//! TCP session routing intentionally remains outside this crate until the next
//! coherent server work unit.

pub mod path;
mod registry;
mod router;
mod router_loop;
mod socket_path;

pub use registry::{Registration, RegistrationError, Registry};
pub use router::{Router, RouterError, RouterEvent, RouterReject};
