use cachain::*;
use std::net::{SocketAddr, TcpListener};
use std::io::Write;
use capnp::serialize;
use std::error::Error;

//const TRUSTED_PEERS: [&str;1] = ["localhost:6969"];
const ADDR: u64 = 0xdeadbeef;

fn main() -> Result<(),Box<dyn Error>> {
    let key = generate();
    let listener = TcpListener::bind("127.0.0.1:6969".parse::<SocketAddr>().unwrap()).unwrap();
    let peers = vec![String::from("a.com"),String::from("b.com")];
    for sstream in listener.incoming() {
        let mut stream = sstream.unwrap();
        println!("Received connection");
        //todo: read addr from incoming packet
        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();

        let ping = reader.get_root::<msg_capnp::ping::Reader>().unwrap();
        println!("Received ping: {:?}",ping);
        let pong = create_pong(ADDR,ping.get_src(),&key,peers.clone());
        stream.write(&pong)?;
    }
    return Ok(());
}
