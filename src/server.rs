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

                let update = UpdateResponse{
                    src:ADDR,
                    dest:update.src,
                    start_hash: update.start_hash.clone(),  // requested start hash
                    chain:db::get_tail(&update.start_hash),
                };
                let update_r = update.to_capnp();
                stream.write(&update_r)?;
            }
            contents::UpdateResponse(up_rdr) => {
                let upd = UpdateResponse::from_reader(up_rdr?)?;
                //TODO: MORE Validation for security, etc
                if !chain::is_valid_chain(
                    &upd.chain,
                    upd.start_hash != upd.chain[0].hash
                ) { 
                    panic!("Received invalid update :sadge:1");
                }
                let succ = db::fast_forward(upd.chain);
                if !succ {
                    panic!("Cannot add new entries :sadge:2");
                }
            }
            contents::Advert(adv_reader) => {
                let adv = Advert::from_reader(adv_reader?)?;
                match &adv.kind {
                    AdvertKind::CE(_hash) => {
                        // May store this has for cross checking?
                        //TODO: s/msgid/msghash/g
                        let upd = Update {src: ADDR, dest: adv.src,start_hash: db::get_tip_hash()};
                        let msg = upd.to_capnp()?;
                        stream.write(&msg)?;
                    }
                    AdvertKind::CR(cr)  => {
                        //TODO: need to store this cert request in memory... somewhere
                        //      and remove it when a chain entry containing it is received
                        print!("Received cert request: {:?}",cr);
                    }
                }
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
