pub mod config;
pub mod linux;
pub mod container;
use std::panic::Location;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum LibContainerError {
    #[error("Mount src: `{src:?}` target: `{target:?}` fs type: `{fs_type:?}`, data: `{data:?}`, err: `{err:?}`")]
    MountError {
        src: Option<String>,
        target: String,
        fs_type: Option<String>,
        data: Option<String>,
        err: nix::Error
    },
    #[error("Set gruops: `{0:?}`, err: `{:1}`")]
    SetGroupsError(String, nix::Error),
    #[error("Nix error: `{0:?}`, '{1:?}'")]
    NixError(nix::Error, &'static Location<'static>),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    SerdeError(#[from] serde_json::error::Error),
    #[error("Infalid UTF8 String")]
    InvalidUtf8Error,
    #[error("Error: {0:?}")]
    Default(String)
}

impl From<std::string::FromUtf8Error> for LibContainerError {
    fn from(_: std::string::FromUtf8Error) -> Self {
       LibContainerError::InvalidUtf8Error 
    }
}

impl From<nix::Error> for LibContainerError {
    #[track_caller]
    fn from(err : nix::Error) -> Self {
        LibContainerError::NixError(err, std::panic::Location::caller())
    }
}
pub type Result<T> = std::result::Result<T, LibContainerError>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
