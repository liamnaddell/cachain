use cachain::*;
use cachain::peers::Peer;
use std::net::{SocketAddr, TcpListener};
use std::io::Write;
use capnp::serialize;
use std::error::Error;
use crate::msg_capnp::msg::contents;
use std::net::TcpStream;
use std::env;
use std::thread;
use cachain::chain::*;

fn handle_conn(mut stream: TcpStream) -> Result<(),Box<dyn Error>> {
    loop {
        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new())?;
        let msg_reader = reader.get_root::<msg_capnp::msg::Reader>()?;
        let contents = msg_reader.get_contents();
        let key = db::get_key();
        match contents.which()? {
            //If they sent a ping, send a pong back on the same channel
            contents::Ping(ping_reader) => {
                let ping = Ping::from_reader(ping_reader?)?;
                let mut socket = stream.peer_addr()?;
                socket.set_port(8069);
                
                // add peer as a proper peer
                let peer_url = format!("{:?}",socket);
                let peer = Peer::from_ping(peer_url.clone(),&ping);
                peers::add_peer(peer);
                println!("[peers] Entered peership with {}", &peer_url);
                
                // send back potential peers
                let peers = peers::peer_urls();
                let pong = create_pong(db::get_addr(),ping.src,&key,peers);
                stream.write(&pong)?;
                println!("Received ping: {:?}",ping);
            }
            //If they sent an Update, send an UpdateResponse back on the same channel
            contents::Update(update_reader) => {
                let update = Update::from_reader(update_reader?)?;
                println!("Received update: {:?}",update);

                let update = UpdateResponse{
                    src:db::get_addr(),
                    dest:update.src,
                    start_hash: update.start_hash.clone(),  // requested start hash
                    chain:db::get_tail(&update.start_hash),
                };
                let update_r = update.to_capnp();
                println!("Sending response: {:?}",update);
                stream.write(&update_r)?;
            }
            // Issue: at the moment, we handle UpdateResponse when we handle Advert(CE)
            //    so we will never hit this code unless UpdateResponse got sent without us requesting
            //If we receive UpdateResponse, record the info
            contents::UpdateResponse(up_rdr) => {
                let upd = UpdateResponse::from_reader(up_rdr?)?;
                println!("Received update_response: {:?}",upd);
                //TODO: MORE Validation for security, etc
                if !chain::is_valid_chain(
                    &upd.chain,
                    upd.start_hash != upd.chain[0].hash
                ) { 
                    panic!("Received invalid update :sadge:1");
                }
                // TODO: if this is a whole chain, then we need to handle the
                // fork case
                let succ = db::fast_forward(upd.chain);
                if !succ {
                    panic!("Cannot add new entries :sadge:2");
                }
            }
            //If we receive a challenge, do nothing until george fixes
            contents::Challenge(ce_reader) => {
                let cer = Challenge::from_reader(ce_reader?)?;
                println!("Received challenge: {:?}",cer);
                //TODO: George fix

                // forward challenge
                let blacklist = cer.src;
                let forwarding_msg = cer.to_msg();
                peers::broadcast(forwarding_msg, blacklist)?;
            }
            //If we receive an advert, send a request on a new channel (Adverts are broadcasted on
            //write-only lines)
            contents::Advert(adv_reader) => {
                let mut adv = Advert::from_reader(adv_reader?)?;
                println!("Received advert: {:?}",adv);
                match &adv.kind {
                    AdvertKind::CE(hash) => {
                        let maybe_hash = db::find_hash(hash);
                        if maybe_hash.is_none() {
                            // May store this has for cross checking?
                            let hash = {
                                if let Some(h) = db::get_tip_hash() { 
                                    h
                                } else {
                                    String::from("")
                                }
                            };
                            println!("Updating chain from peers");
                            
                            // Perform update request/response to the sender of advert
                            peers::update_chain(hash, adv.src);

                            // forward the advert to other peers
                            let blacklist = adv.src;
                            // Special case: update src to self, so peers can send update request to us
                            adv.src = db::get_addr();     
                            let forwarding_msg = adv.to_msg()?;
                            peers::broadcast(forwarding_msg, blacklist)?;
                        }
                    }
                    //If we received a cert reqeust, check if we are the elector, or just broadcast
                    //the message
                    AdvertKind::CR(cr)  => {
                        println!("Received cert request: {:?}",cr);
                        let ni = db::current_elector();
                        if ni.addr == db::get_addr() {
                            let chal = Challenge::new(cr.src,"この気持ちはまだそっとしまっておきたい".to_string());
                            println!("Created challenge: {:?}",chal);
                            //TODO: Fix this api w/ real values + better func
                            peers::broadcast(chal.to_msg(),0)?;
                        }

                        //TODO: need to store this cert request in memory... somewhere
                        //      and remove it when a chain entry containing it is received
                        
                        // forward cert request to other peers
                        let blacklist = adv.src;
                        let forwarding_msg = adv.to_msg()?;
                        peers::broadcast(forwarding_msg, blacklist)?;
                    }
                }
            }
            _ => {
                println!("Unknown msg type received lol");
            }
        };
    }

}

fn verifier_thread(domain: String) -> Result<(),Box<dyn Error>> {
    let ces: Vec<ChainEntry> = db::find_by_domain(&domain);
    if ces.len() != 0 {
        //we are already verified
        println!("[verifier_thread] Our website is already verified");
        return Ok(());
    }
    println!("[verifier_thread] Creating CertRequest to become verified");
    let ce = CertRequest::new(domain);
    //TODO: add real thing in here
    //
    let msg_builder = ce.to_advert_builder();
    let msg = serialize::write_message_to_words(&msg_builder);
    peers::broadcast(msg,0)?;
    return Ok(());
}

fn main() -> Result<(),Box<dyn Error>> {
    let (domain,peer,peerno) = {
        let args:Vec<String> = env::args().collect();
        if args.len() < 2 {
            println!("usage: <domain> <peer>");
            std::process::exit(1);
        }
        let domain = &args[1];
        if args.len() == 2 {
            (domain.clone(),None,5)
        } else {
            let arg = args[2].to_string()+":8069";
            println!("Initializing peer list with {}",arg);
            (domain.clone(),Some(arg),5)
        }
    };
    db::load_db("server_db.json");
    peers::init(domain.clone()+":8069",peer.clone(),peerno);
    //TODO: FF chain
    if peer == None {
        println!("Creating new genesis from {domain}");
        db::generate_new_genesis(domain);
    } else {
        //thread for verifying the server
        thread::spawn(move || {
            let res = verifier_thread(domain);
            if let Err(e) = res {
                println!("Error in verifier thread: {e}");
            } else {
                println!("[verifier_thread]: exited succesfully");
            }
        });
    }
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
