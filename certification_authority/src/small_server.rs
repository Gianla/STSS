//! Main little, single-threaded server to support the main Server's signing requests.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmallServerRunError {}

pub struct SmallServer {}

impl SmallServer {
    fn build() -> Self {
        Self {}
    }

    fn run() -> Result<(), SmallServerRunError> {
        Ok(())
    }
}
