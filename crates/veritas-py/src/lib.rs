//! # veritas-py
//!
//! Python bindings for the VERITAS Protocol.
//!
//! This crate provides Python bindings using PyO3:
//! - Pythonic API wrapper
//! - Async support via pyo3-asyncio (future)
//! - Type hints for IDE support
//!
//! ## Usage
//!
//! ```python
//! import veritas
//!
//! # Create identity
//! client = veritas.Client()
//! client.create_identity()
//!
//! # Send message
//! hash = client.send_message(recipient_id, "Hello!")
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

use pyo3::prelude::*;

/// Returns the library version.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Python module definition.
#[pymodule]
fn veritas(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
