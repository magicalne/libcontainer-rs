pub mod config;
pub mod linux;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum LibContainerError {
    #[error("Nix error")]
    NixError(nix::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error)
}

pub type Result<T> = std::result::Result<T, LibContainerError>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
