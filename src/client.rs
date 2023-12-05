use cachain::*;
//use std::net::{ToSocketAddrs,TcpStream};
//use capnp::serialize;
//use std::io::Write;
use std::error::Error;
use clap::Parser;
use std::path::Path;
use cachain::chain::ChainEntry;

#[derive(Parser)]
struct Args {
    #[arg(short,long,default_value_t = false)]
    in_memory: bool,
    peer: String,
    #[arg(long,default_value_t = 5)]
    peerno: usize,
    #[arg(short,long)]
    loc: Option<String>,
}

fn dump_ce(path: &str, ce: &ChainEntry) -> Result<(), Box<dyn Error>> {
    //TODO: Implement!
    Ok(())
}

fn main() -> Result<(),Box<dyn Error>> {
    let args = Args::parse();
    let peer = args.peer;

    //a monad is a monoid in the category of endofunctors
    let path = args.loc;

    db::load_db("client_db.json");
    peers::init(None,Some(peer),args.peerno);
    peers::start_update_thread();
    let rx = db::update_channel();
    let chain = db::get_chain();

    if let Some(ref p) = path {
        for ce in chain.iter() {
            if let Err(e) = dump_ce(p,ce) {
                println!("Error dumping certs: {}",e);
            }
        }
    }
    loop {
        let ce = rx.recv()?;
        if let Some(ref p) = path {
            if let Err(e) = dump_ce(p,&ce) {
                println!("Error dumping certs: {}",e);
            }
        }
        println!("New update: {}",ce);
    }
    return Ok(());
}
