use cachain::*;
use std::net::{ToSocketAddrs,TcpStream};
use capnp::serialize;
use std::io::Write;
use std::error::Error;
use std::env;

const MY_ADDR: u64 = 10203;

fn main() -> Result<(),Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let peer = {
        if args.len() == 1 {
            "127.0.0.1:8069"
        } else {
            &args[1]
        }
    };
    let db = load_db("client_db.json");
    println!("{}",peer);
    let mut addrs = peer.to_socket_addrs().unwrap();
    let mut socket = addrs.next().unwrap();
    socket.set_port(8069);
    println!("Connecting to peer {} with ip {:?}",peer,socket);
    let mut stream = TcpStream::connect(socket).unwrap();
    //send ping
    let ping = Ping {src:MY_ADDR,dest:0,key:private_to_public(&db.pkey)};
    let msg_ping = ping.to_msg()?;

    stream.write(&msg_ping)?;

    let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();

    //TODO: add pong info to running list of peers
    let pong = reader.get_root::<msg_capnp::pong::Reader>().unwrap();
    println!("{:?}",pong);
    deserialize_pubkey(pong.get_key()?.to_string()?);

    let update = Update {src:MY_ADDR,dest:pong.get_src(),start_msgid:0,end_msgid:0};
    let msg_update = update.to_capnp()?;

    stream.write(&msg_update)?;
    let reader2 = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();
    let update_response = reader2.get_root::<msg_capnp::update_response::Reader>()?;
    println!("{:?}", update_response);
    return Ok(());
}
