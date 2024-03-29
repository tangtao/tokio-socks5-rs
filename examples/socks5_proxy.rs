extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_socks5;
extern crate trust_dns_resolver;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::io;

use futures::{future, Future, Stream};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::Core;
use tokio_io::io::copy;
use tokio_io::AsyncRead;
use trust_dns_resolver::ResolverFuture;

fn main() {
    drop(env_logger::init());

    let addr = "127.0.0.1:8080".parse().unwrap();
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();
    let resolver = ResolverFuture::from_system_conf(&handle).unwrap();

    println!("Listening for socks5 proxy connections on {}", addr);
    let streams = listener.incoming().and_then(|(socket, addr)| {
        debug!("{}", addr);
        tokio_socks5::serve(socket)
    });

    let server = streams.for_each(move |(c1, host, port)| {
        println!("{}", addr);
        println!("remote address: {}:{}", host, port);

        let handle1 = handle.clone();

        let look_up = resolve(&host, &resolver);
        let pair = look_up
            .and_then(move |addr| {
                TcpStream::connect(&SocketAddr::new(addr, port), &handle1).map(|c2| (c1, c2))
            });

        let pipe = pair.and_then(|(c1, c2)| {
            let (reader1, writer1) = c1.split();
            let (reader2, writer2) = c2.split();
            let half1 = copy(reader1, writer2);
            let half2 = copy(reader2, writer1);
            half1.join(half2).map(|(h1, h2)| (h1.0, h2.0))
        });

        let finish = pipe.map(|data| {
            println!("received {} bytes, responsed {} bytes", data.0, data.1)
        }).map_err(|e| info!("{}", e));

        handle.spawn(finish);
        Ok(())
    });

    lp.run(server).unwrap();
}

fn resolve(host: &str, resolver: &ResolverFuture) -> Box<Future<Item = IpAddr, Error = io::Error>> {
    if let Ok(addr) = IpAddr::from_str(&host) {
        return Box::new(future::ok(addr));
    }

    let res = resolver.lookup_ip(&host).then(move |res| {
        match res {
            Ok(r) => if let Some(addr) = r.iter().next() {
                future::ok(addr)
            } else {
                future::err(other("no ip return"))
            },
            Err(_) => future::err(other("resolve fail")),
        }
    });

    Box::new(res)
}

pub fn other(desc: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
