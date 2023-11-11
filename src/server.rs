use cachain::*;
use std::net::{SocketAddr, TcpListener};
use std::io::Write;
use capnp::serialize;
use std::error::Error;
use crate::msg_capnp::msg::contents;
use std::net::TcpStream;
use std::env;

const ADDR: u64 = 0xdeadbeef;

fn handle_conn(mut stream: TcpStream) -> Result<(),Box<dyn Error>> {
    loop {
        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new())?;
        let msg_reader = reader.get_root::<msg_capnp::msg::Reader>()?;
        let contents = msg_reader.get_contents();
        let key = db::get_key();
        match contents.which()? {
            contents::Ping(ping_reader) => {
                let ping = Ping::from_reader(ping_reader?)?;
                let ip = stream.peer_addr()?.to_string();
                peers::add_potential(&ip);
                let peers = peers::peer_urls();
                let pong = create_pong(ADDR,ping.src,&key,peers);
                stream.write(&pong)?;
                println!("Received ping: {:?}",ping);
            }
            contents::Update(update_reader) => {
                let update = Update::from_reader(update_reader?)?;
                println!("Received update: {:?}",update);
                let update_r = create_update_response(ADDR,update.src,db::get_chain());
                stream.write(&update_r)?;
            }
            _ => {
                println!("Unknown msg type received lol");
            }
        };
    }

}

fn main() -> Result<(),Box<dyn Error>> {
    let (peer,peerno) = {
        let args:Vec<String> = env::args().collect();
        if args.len() == 1 {
            (None,0)
        } else {
            let arg = args[1].to_string()+":8069";
            println!("Initializing peer list with {}",arg);
            (Some(arg),5)
        }
    };
    db::load_db("server_db.json");
    peers::init(peer,peerno);
    let listener = TcpListener::bind("0.0.0.0:8069".parse::<SocketAddr>().unwrap()).unwrap();
    for sstream in listener.incoming() {
        let stream = sstream?;
        println!("Received connection");
        let maybe_error = handle_conn(stream);
        if let Err(e) = maybe_error {
            println!("connection ended with error: {}",e);
        }
    }
    return Ok(());
}
