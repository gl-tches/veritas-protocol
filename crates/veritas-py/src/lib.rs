//! # veritas-py
//!
//! Python bindings for VERITAS protocol.
//!
//! Provides a Pythonic API for using VERITAS from Python applications.

use pyo3::prelude::*;

/// Get the library version.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// VERITAS Python module.
#[pymodule]
fn veritas(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
