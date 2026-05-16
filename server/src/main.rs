pub mod server;
pub mod user;
pub mod connection_handler;
pub mod config;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use server::{KeyContext, RuntimeContext, STSServer, ServerContext};

fn main() {
    // todo: change the stdout
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let ip = IpAddr::from_str("localhost").unwrap();
    /*
    let context = ServerContext::new(
        SocketAddr::new(ip, 50000),
        RuntimeContext::new(4, 0),
        KeyContext::new()
    );
    let server = STSServer::build_from_context()
     */
}
