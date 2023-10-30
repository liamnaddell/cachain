use cachain::*;
use std::net::{SocketAddr, ToSocketAddrs,TcpStream};
use std::str::FromStr;
use capnp::serialize;
use std::io::Write;

const trusted_peers: [&str;1] = ["127.0.0.1:6969"];
const my_addr: u64 = 10203;

fn main() {
    for peer in trusted_peers {
        let mut addrs = peer.to_socket_addrs().unwrap();
        let mut socket = addrs.next().unwrap();
        socket.set_port(6969);
        println!("Connecting to peer {} with ip {:?}",peer,socket);
        let mut stream = TcpStream::connect(socket).unwrap();
        //send ping
        let ping = create_ping(my_addr,0);

        stream.write(&ping);

        let reader = serialize::read_message(stream,capnp::message::ReaderOptions::new()).unwrap();

        let pong = reader.get_root::<msg_capnp::pong::Reader>().unwrap();

        println!("{:?}",pong);





        //wait for pong
    }
    println!("Hello World {}",add(1,2));
}
