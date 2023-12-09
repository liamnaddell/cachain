use cachain::*;
use std::error::Error;
use std::io::Write;
use std::fs::File;
use std::fs;
use clap::Parser;
use cachain::chain::ChainEntry;

fn dump_ce(path: &str, ce: &ChainEntry) -> Result<(), Box<dyn Error>> {
    let text = &ce.verifier_signature;
    let filename = &ce.hash;
    //XXX: Not cross-compatible, but tbh, windows users r not allowed
    let pp = path.to_string()+"/"+&filename;
    let mut file = File::create(&pp)?;
    file.write_all(text.as_slice())?;

    Ok(())
}

#[derive(Parser)]
struct Args {
    #[arg(short,long,default_value_t = false)]
    in_memory: bool,
    peer: String,
    #[arg(long,default_value_t = 5)]
    peerno: usize,
    #[arg(short,long)]
    loc: Option<String>,
    #[arg(long)]
    dump_cert: Option<String>,
}


use std::thread;
use std::time::Duration;
fn dump_domain(path:&str,domain: &str) -> Result<(),Box<dyn Error>> {
    loop {
        let cs = db::find_by_domain(domain);
        if cs.len() != 0 {
            let ce = &cs[cs.len()-1];
            return dump_ce(path,ce);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn main() -> Result<(),Box<dyn Error>> {
    let args = Args::parse();
    let peer = args.peer;

    if args.in_memory {
        db::in_memory(None);
    } else {
        db::load_db("client_db.json",None);
    } 


    if let Some(ref domain) = args.dump_cert {
        let path = {
            if let Some(p) = args.loc {
                p
            } else {
                ".".to_string()
            }
        };
        return dump_domain(&path,domain);
    };

    //a monad is a monoid in the category of endofunctors
    let path = args.loc;


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
