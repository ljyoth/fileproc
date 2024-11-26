use std::{borrow::Cow, path::PathBuf};

#[derive(Debug, Clone)]
pub struct Process {
    id: usize,
    path: PathBuf,
}

impl Process {
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn name(&self) -> Cow<'_, str> {
        self.path().file_name().unwrap().to_string_lossy()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;
