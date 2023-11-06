use cachain::*;
use std::net::{ToSocketAddrs,TcpStream};
use capnp::serialize;
use std::io::Write;
use std::error::Error;

const TRUSTED_PEERS: [&str;1] = ["127.0.0.1:6969"];
const MY_ADDR: u64 = 10203;

fn main() -> Result<(),Box<dyn Error>> {
    let db = load_db("client_db.json");
    for peer in TRUSTED_PEERS {
        let mut addrs = peer.to_socket_addrs().unwrap();
        let mut socket = addrs.next().unwrap();
        socket.set_port(6969);
        println!("Connecting to peer {} with ip {:?}",peer,socket);
        let mut stream = TcpStream::connect(socket).unwrap();
        //send ping
        let ping = create_ping(MY_ADDR,0,&db.pkey);

        stream.write(&ping)?;

        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();

        //TODO: add pong info to running list of peers
        let pong = reader.get_root::<msg_capnp::pong::Reader>().unwrap();
        println!("{:?}",pong);
        deserialize_pubkey(pong.get_key()?.to_string()?);

        let update = create_update(MY_ADDR,pong.get_src(),0,0);

        stream.write(&update)?;
        let update_response = reader.get_root::<msg_capnp::update_response::Reader>()?;
        println!("{:?}", update_response);
    }
    return Ok(());
}
