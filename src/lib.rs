//! A simple socks5 proxy library.

extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

mod client;
mod server;

pub use server::serve;
