use cachain::*;
//use std::net::{ToSocketAddrs,TcpStream};
//use capnp::serialize;
//use std::io::Write;
use std::error::Error;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short,long,default_value_t = false)]
    in_memory: bool,
    peer: String,
    #[arg(long,default_value_t = 5)]
    peerno: usize,
}

fn main() -> Result<(),Box<dyn Error>> {
    let args = Args::parse();
    let peer = args.peer;

    db::load_db("client_db.json");
    /*let mut addrs = peer.to_socket_addrs().unwrap();
    let mut socket = addrs.next().unwrap();
    socket.set_port(8069);*/
    /*println!("Connecting to peer {} with ip {:?}",peer,socket);
    let mut stream = TcpStream::connect(socket).unwrap();
    //send ping
    let ping = Ping {src:MY_ADDR,dest:0,key:private_to_public(&db::get_key())};
    let msg_ping = ping.to_msg()?;

    stream.write(&msg_ping)?;

    let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();*/

    /*
    let pong = reader.get_root::<msg_capnp::pong::Reader>().unwrap();
    println!("{:?}",pong);
    deserialize_pubkey(&pong.get_key()?.to_string()?);

    let update = Update {src:MY_ADDR,dest:pong.get_src(),start_hash:"".to_string()};
    let msg_update = update.to_capnp()?;
    */
    /*stream.write(&msg_update)?;
    let reader2 = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();
    let update_response = reader2.get_root::<msg_capnp::update_response::Reader>()?;
    println!("{:?}", update_response);*/

    //TODO: Add option for maintaining list of currently valid ca certificates
    peers::init(None,Some(peer),args.peerno);
    peers::start_update_thread();
    return Ok(());
}
