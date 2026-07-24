#![forbid(unsafe_code)]

//! Secure server listeners, local terminal registration, and encrypted session routing.

pub mod path;
mod registry;
mod registry_validation;
mod router;
mod router_loop;
mod router_registration;
mod runtime;
mod runtime_accept;
mod runtime_error;
mod runtime_handle;
mod runtime_handler;
mod runtime_lifecycle;
mod runtime_state;
mod session;
mod session_slot;
mod session_table;
mod session_wait;
mod socket_path;

pub use registry::{Registration, RegistrationError, Registry};
pub use router::{Router, RouterError, RouterEvent, RouterReject};
pub use runtime::Runtime;
pub use runtime_error::RuntimeError;
pub use runtime_handle::{HandleError, RuntimeHandle};
pub use session_table::{SessionState, SessionTable, SessionTableError};
