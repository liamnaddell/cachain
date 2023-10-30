use cachain::*;
use std::net::{SocketAddr, ToSocketAddrs,TcpStream,TcpListener};
use std::str::FromStr;
use std::io::Write;

const trusted_peers: [&str;1] = ["localhost:6969"];
const addr: u64 = 0xdeadbeef;

fn main() {
    let key = generate();
    for peer in trusted_peers {
        let mut addrs = peer.to_socket_addrs().unwrap();
        let mut socket = addrs.next().unwrap();
        socket.set_port(6969);
        println!("Connecting to peer {} with ip {:?}",peer,socket);
        let listener = TcpListener::bind("127.0.0.1:6969".parse::<SocketAddr>().unwrap()).unwrap();
        for sstream in listener.incoming() {
            let mut stream = sstream.unwrap();
            println!("Received connection");
            //todo: read addr from incoming packet
            let pong = create_pong(addr,0);
            stream.write(&pong);
        }
    }
    println!("Hello World {}",add(1,2));
}
