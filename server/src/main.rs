// todo: remove these
#![allow(unused)]

pub mod config;
pub mod connection_handler;
pub mod database;
pub mod server;

use server::{KeyContext, RuntimeContext, STSServer, ServerContext};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::Level;

fn main() {
    let ip = IpAddr::from_str("localhost").unwrap();
    // let context = ServerContext::new(
    // SocketAddr::new(ip, 50000),
    // RuntimeContext::new(4, 0),
    // KeyContext::new()
    // );
    // let server = STSServer::build_from_context()
}
