use cachain::*;
use std::net::{SocketAddr, ToSocketAddrs,TcpStream};
use std::str::FromStr;

const trusted_peers: [&str;1] = ["127.0.0.1:6969"];

fn main() {
    for peer in trusted_peers {
        let mut addrs = peer.to_socket_addrs().unwrap();
        let mut socket = addrs.next().unwrap();
        socket.set_port(6969);
        println!("Connecting to peer {} with ip {:?}",peer,socket);
        let listener = TcpStream::connect(socket).unwrap();
        //send ping

        //wait for pong
    }
    println!("Hello World {}",add(1,2));
}
