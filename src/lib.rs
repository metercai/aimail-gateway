// aimail-gateway shared library.

pub mod base;
pub mod board;
pub mod core;

// Re-export the mailin types that handlers need, so downstream crates do not
// have to depend on mailin directly.
pub use mailin::{Action, Handler, Response, SessionBuilder};
