use cachain::*;
use std::net::{SocketAddr, ToSocketAddrs,TcpStream};
use std::str::FromStr;

const trusted_peers: [&str;1] = ["localhost"];

fn main() {
    for peer in trusted_peers {
        println!("Processing peer {}",peer);
        let mut socket = SocketAddr::from_str(peer).unwrap();
        socket.set_port(6969);
        let listener = TcpStream::connect(socket).unwrap();
        //send ping

        //wait for pong
    }
    println!("Hello World {}",add(1,2));
}
