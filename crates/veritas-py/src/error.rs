//! Error handling for Python bindings.

use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use veritas_core::CoreError;

/// VERITAS error exception for Python.
///
/// This exception is raised when VERITAS operations fail.
#[pyclass(extends=PyException)]
pub struct VeritasError;

impl VeritasError {
    /// Create a new VeritasError from a CoreError.
    pub fn new_err(err: CoreError) -> PyErr {
        PyErr::new::<VeritasError, _>(err.to_string())
    }
}

/// Convert CoreError to PyErr.
///
/// This is a helper trait to avoid orphan rule issues.
pub trait IntoPyErr {
    fn into_py_err(self) -> PyErr;
}

impl IntoPyErr for CoreError {
    fn into_py_err(self) -> PyErr {
        VeritasError::new_err(self)
    }
}

/// Register the error type with Python.
pub fn register_error(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("VeritasError", m.py().get_type::<VeritasError>())?;
    Ok(())
}
