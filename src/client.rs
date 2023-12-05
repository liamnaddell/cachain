use cachain::*;
use std::error::Error;
use std::io::Write;
use std::fs::File;
use std::fs;
use clap::Parser;
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
    let text = &ce.verifier_signature;
    let filename = &ce.hash;
    //XXX: Not cross-compatible, but tbh, windows users r not allowed
    let pp = path.to_string()+"/"+&filename;
    let mut file = File::create(&pp)?;
    file.write_all(text.as_slice())?;

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
        println!("Dumping certs in database");
        //ignore errors like "the directory already exists"
        let _ = fs::create_dir(p);
        for ce in chain.iter() {
            if let Err(e) = dump_ce(p,ce) {
                println!("Error dumping certs: {}",e);
            }
        }
    }
    println!("Entering main loop");
    loop {
        let ce = rx.recv()?;
        println!("New update: {}",ce);
        if let Some(ref p) = path {
            println!("Dumping new cert");
            if let Err(e) = dump_ce(p,&ce) {
                println!("Error dumping certs: {}",e);
            }
        }
    }
}
