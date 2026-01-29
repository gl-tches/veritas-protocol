//! # veritas-py
//!
//! Python bindings for VERITAS protocol.
//!
//! Provides a Pythonic API for using VERITAS from Python applications.

use pyo3::prelude::*;

mod client;
mod error;
mod identity;
mod safety;

use client::VeritasClient;
use error::register_error;
use identity::{IdentityInfo, IdentitySlots};
use safety::SafetyNumber;

/// Get the library version.
///
/// Returns:
///     str: The version string.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// VERITAS Python module.
///
/// This module provides Python bindings for the VERITAS protocol,
/// a post-quantum secure, decentralized messaging protocol with
/// blockchain verification and offline P2P capability.
///
/// Example:
///     >>> import veritas
///     >>> print(veritas.version())
///     >>> client = veritas.VeritasClient()
///     >>> client.unlock(b"password")
///     >>> identity = client.create_identity("My Identity")
#[pymodule]
fn veritas(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // Register error type
    register_error(py, m)?;

    // Register classes
    m.add_class::<VeritasClient>()?;
    m.add_class::<IdentityInfo>()?;
    m.add_class::<IdentitySlots>()?;
    m.add_class::<SafetyNumber>()?;

    // Register functions
    m.add_function(wrap_pyfunction!(version, m)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = version();
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }

    // Note: Full integration tests should be written in Python.
    // pyo3 tests with cdylib crate type have linking issues.
    // See tests/ directory for Python-based integration tests.
}
