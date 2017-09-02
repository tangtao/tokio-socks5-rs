extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

use std::time::Duration;
use std::io;
use std::str;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use futures::future;
use futures::Future;
use tokio_io::io::{read_exact, write_all};
use tokio_core::net::TcpStream;
use tokio_timer::Timer;

mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
}

pub fn serve(conn: TcpStream) -> Box<Future<Item = (TcpStream, String), Error = io::Error>> {
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

    // there's one byte which is reserved for future use, so we read it and discard it.
    let resv = command.and_then(|c| read_exact(c, [0u8]));
    let adress_type = resv.and_then(|(conn, _)| read_exact(conn, [0u8]));
    let address = mybox(adress_type.and_then(move |(c, buf)| {
        match buf[0] {
            // For IPv4 addresses, we read the 4 bytes for the address as
            // well as 2 bytes for the port.
            v5::TYPE_IPV4 => mybox(read_exact(c, [0u8; 6]).and_then(|(c, buf)| {
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                let addr = SocketAddrV4::new(addr, port);
                mybox(future::ok((c, format!("{}", addr))))
            })),

            // For IPv6 addresses there's 16 bytes of an address plus two
            // bytes for a port, so we read that off and then keep going.
            v5::TYPE_IPV6 => mybox(read_exact(c, [0u8; 18]).and_then(|(conn, buf)| {
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
                mybox(future::ok((conn, format!("{}", addr))))
            })),

            // The SOCKSv5 protocol not only supports proxying to specific
            // IP addresses, but also arbitrary hostnames.
            v5::TYPE_DOMAIN => mybox(
                read_exact(c, [0u8])
                    .and_then(|(conn, buf)| {
                        read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    })
                    .and_then(|(conn, buf)| {
                        let hostname = &buf[..buf.len() - 2];
                        let hostname = if let Ok(hostname) = str::from_utf8(hostname) {
                            hostname
                        } else {
                            return mybox(future::err(other("hostname include invalid utf8")));
                        };

                        let pos = buf.len() - 2;
                        let port = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
                        mybox(future::ok(
                            (conn, format!("{}:{}", hostname.to_string(), port)),
                        ))
                    }),
            ),
            n => {
                let msg = format!("unknown address type, received: {}", n);
                mybox(future::err(other(&msg)))
            }
        }
    }));

    // Sending connection established message immediately to client.
    // This some round trip time for creating socks connection with the client.
    // But if connection failed, the client will get connection reset error.
    let handshake_finish = mybox(address.and_then(move |(conn, addr)| {
        let resp = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43];
        write_all(conn, resp).map(move |(conn, _)| (conn, addr))
    }));

    let timer = Timer::default();
    let timeout = timer
        .timeout(handshake_finish, Duration::new(10, 0))
        .map_err(|_| other("handshake timeout"));

    mybox(timeout.and_then(|(conn, addr)| future::ok((conn, addr))))
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item = F::Item, Error = F::Error>> {
    Box::new(f)
}


fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
