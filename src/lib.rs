extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;

use std::io;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;
use std::time::Duration;

use futures::future;
use futures::Future;
use tokio_io::io::{copy, read_exact, write_all, Window};
use tokio_io::AsyncRead;
use tokio_core::net::TcpStream;
use tokio_core::reactor::{Handle, Timeout};
use trust_dns::client::{BasicClientHandle, ClientHandle};
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
}

// Data used to when processing a client to perform various operations over its
// lifetime.
pub struct Client {
    pub dns: BasicClientHandle,
    pub handle: Handle,
}

impl Client {
    pub fn new(client: BasicClientHandle, handle: Handle) -> Client {
        return Client {
            dns: client.clone(),
            handle: handle.clone(),
        };
    }

    pub fn serve(self, conn: TcpStream) -> Box<Future<Item = (u64, u64), Error = io::Error>> {
        // socks version, only support version 5.
        let version = read_exact(conn, [0u8; 2]).and_then(|(conn, buf)| if buf[0] == v5::VERSION {
            Ok((conn, buf))
        } else {
            Err(other("unknown version"))
        });

        // ignore socks method
        let method = version.and_then(|(conn, buf)| read_exact(conn, [0u8, buf[1] as u8]));

        // send confirmation: version 5, no authentication required
        let part1 = method.and_then(|(conn, _)| write_all(conn, [v5::VERSION, v5::METH_NO_AUTH]));

        // check version
        let ack = part1.and_then(|(conn, _)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| if buf[0] == v5::VERSION {
                Ok(conn)
            } else {
                Err(other("didn't confirm with v5 version"))
            })
        });
        // checkout cmd
        let command = ack.and_then(|conn| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| if buf[0] == v5::CMD_CONNECT {
                Ok(conn)
            } else {
                Err(other("unsupported command"))
            })
        });

        let mut dns = self.dns.clone();
        // there's one byte which is reserved for future use, so we read it and discard it.
        let resv = command.and_then(|c| read_exact(c, [0u8]));
        let atyp = resv.and_then(|(conn, _)| read_exact(conn, [0u8]));
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                // For IPv4 addresses, we read the 4 bytes for the address as
                // well as 2 bytes for the port.
                v5::TYPE_IPV4 => mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let addr = SocketAddrV4::new(addr, port);
                    (c, SocketAddr::V4(addr))
                })),

                // For IPv6 addresses there's 16 bytes of an address plus two
                // bytes for a port, so we read that off and then keep going.
                v5::TYPE_IPV6 => mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                    let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                    let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                    let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                    let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                    let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                    let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                    let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                    let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                    let addr = SocketAddrV6::new(addr, port, 0, 0);
                    (conn, SocketAddr::V6(addr))
                })),

                // The SOCKSv5 protocol not only supports proxying to specific
                // IP addresses, but also arbitrary hostnames. This allows
                // clients to perform hostname lookups within the context of the
                // proxy server rather than the client itself.
                v5::TYPE_DOMAIN => mybox(
                    read_exact(c, [0u8])
                        .and_then(|(conn, buf)| {
                            read_exact(conn, vec![0u8; buf[0] as usize + 2])
                        })
                        .and_then(move |(conn, buf)| {
                            let (name, port) = match name_port(&buf) {
                                Ok(UrlHost::Name(name, port)) => (name, port),
                                Ok(UrlHost::Addr(addr)) => return mybox(future::ok((conn, addr))),
                                Err(e) => return mybox(future::err(e)),
                            };

                            let ipv4 = dns.query(name, DNSClass::IN, RecordType::A)
                                .map_err(|e| other(&format!("dns error: {}", e)))
                                .and_then(move |r| get_addr(r, port));
                            mybox(ipv4.map(|addr| (conn, addr)))
                        }),
                ),

                n => {
                    let msg = format!("unknown address type, received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }
        }));

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep ahold of any
        // possible error in the connection phase to handle it in a moment.
        let handle = self.handle.clone();
        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
        }));

        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) | Err(..) => addr,
            };
            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| c2.map(|c2| (c1, c2)))
        }));

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 10 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.
        let timeout = Timeout::new(Duration::new(10, 0), &self.handle).unwrap();
        let pair = mybox(handshake_finish.map(Ok).select(timeout.map(Err)).then(
            |res| {
                match res {
                    // The handshake finished before the timeout fired, so we
                    // drop the future representing the timeout, canceling the
                    // timeout, and then return the pair of connections the
                    // handshake resolved with.
                    Ok((Ok(pair), _timeout)) => Ok(pair),

                    // The timeout fired before the handshake finished. In this
                    // case we drop the future representing the handshake, which
                    // cleans up the associated connection and all other
                    // resources.
                    //
                    // This automatically "cancels" any I/O associated with the
                    // handshake: reads, writes, TCP connects, etc. All of those
                    // I/O resources are owned by the future, so if we drop the
                    // future they're all released!
                    Ok((Err(()), _handshake)) => Err(other("timeout during handshake")),

                    // One of the futures (handshake or timeout) hit an error
                    // along the way. We're not entirely sure which at this
                    // point, but in any case that shouldn't happen, so we just
                    // keep propagating along the error.
                    Err((e, _other)) => Err(e),
                }
            },
        ));

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        mybox(pair.and_then(|(c1, c2)| {
            let (reader1, writer1) = c1.split();
            let (reader2, writer2) = c2.split();

            let half1 = copy(reader1, writer2);
            let half2 = copy(reader2, writer1);
            half1.join(half2).map(|(item1, item2)| (item1.0, item2.0))
        }))
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item = F::Item, Error = F::Error>> {
    Box::new(f)
}


fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(Name, u16),
    Addr(SocketAddr),
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = try!(str::from_utf8(hostname).map_err(|_e| {
        other("hostname buffer provided was not valid utf-8")
    }));
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)));
    }
    let name = try!(
        Name::parse(hostname, Some(&Name::root()))
            .map_err(|e| { io::Error::new(io::ErrorKind::Other, e.to_string()) })
    );
    Ok(UrlHost::Name(name, port))
}

// Extracts the first IP address from the response.
fn get_addr(response: Message, port: u16) -> io::Result<SocketAddr> {
    if response.get_response_code() != ResponseCode::NoError {
        return Err(other("resolution failed"));
    }
    let addr = response
        .get_answers()
        .iter()
        .filter_map(|ans| match *ans.get_rdata() {
            RData::A(addr) => Some(IpAddr::V4(addr)),
            RData::AAAA(addr) => Some(IpAddr::V6(addr)),
            _ => None,
        })
        .next();

    match addr {
        Some(addr) => Ok(SocketAddr::new(addr, port)),
        None => Err(other("no address records in response")),
    }
}
