extern crate env_logger;
extern crate futures;
extern crate tokio_core;
extern crate trust_dns;
extern crate tokio_socks5;

use std::env;
use std::net::SocketAddr;
use std::str;

use futures::future;
use futures::{Future, Stream};
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use trust_dns::client::ClientFuture;
use trust_dns::udp::UdpClientStream;
use tokio_socks5::Client;

fn main() {
    drop(env_logger::init());

    // Take the first command line argument as an address to listen on, or fall
    // back to just some localhost default.
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    // Here we create the event loop.
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    // This is the address of the DNS server we'll send queries to. If
    // external servers can't be used in your environment, you can substitue
    // your own.
    let dns = "8.8.8.8:53".parse().unwrap();
    let (stream, sender) = UdpClientStream::new(dns, handle.clone());
    let client = ClientFuture::new(stream, sender, handle.clone(), None);

    // Construct a future representing our server. This future processes all
    // incoming connections and spawns a new task for each client which will do
    // the proxy work.
    //
    // This essentially means that for all incoming connections, those received
    // from `listener`, we'll create an instance of `Client` and convert it to a
    // future representing the completion of handling that client. This future
    // itself is then *spawned* onto the event loop to ensure that it can
    // progress concurrently with all other connections.
    println!("Listening for socks5 proxy connections on {}", addr);
    let clients = listener.incoming().map(move |(socket, addr)| {
        (Client {
            dns: client.clone(),
            handle: handle.clone(),
        }.serve(socket), addr)
    });
    let handle = lp.handle();
    let server = clients.for_each(|(client, addr)| {
        handle.spawn(client.then(move |res| {
            match res {
                Ok((a, b)) => {
                    println!("proxied {}/{} bytes for {}", a, b, addr)
                }
                Err(e) => println!("error for {}: {}", addr, e),
            }
            future::ok(())
        }));
        Ok(())
    });

    // Now that we've got our server as a future ready to go, let's run it!
    //
    // This `run` method will return the resolution of the future itself, but
    // our `server` futures will resolve to `io::Result<()>`, so we just want to
    // assert that it didn't hit an error.
    lp.run(server).unwrap();
}

