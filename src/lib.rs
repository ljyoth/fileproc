use std::{borrow::Cow, path::PathBuf};


#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;
