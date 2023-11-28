use cachain::*;
use cachain::peers::Peer;
use std::net::{SocketAddr, TcpListener};
use std::io::{self, Write};
use capnp::serialize;
use std::error::Error;
use crate::msg_capnp::msg::contents;
use std::net::TcpStream;
use std::env;
use std::thread;
use std::sync::mpsc::channel;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::{Arc, RwLock};
use tokio::io::{copy, split, sink, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webpki::types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use openssl::{pkey::PKey, x509::{X509, X509NameBuilder}, asn1::Asn1Time, bn::BigNum};
use cachain::chain::*;
use tokio::runtime::Runtime;


fn handle_conn(mut stream: TcpStream, tx: Sender<String>) -> Result<(),Box<dyn Error>> {
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
                tx.send(cer.chal_str.clone());

                // forward challenge
                let blacklist = cer.src;
                let forwarding_msg = cer.to_msg();
                peers::broadcast(forwarding_msg, blacklist)?;
            }
            //If we receive an advert, send a request on a new channel (Adverts are broadcasted on
            //write-only lines)
            contents::Advert(adv_reader) => {
                let mut adv = Advert::from_reader(adv_reader?)?;
                println!("Received advert: {:#?}",adv);
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
                        println!("Received cert request: {:#?}",cr);
                        let ni = db::current_elector();
                        if ni.addr == db::get_addr() {
                            let chalstr = "この気持ちはまだそっとしまっておきたい".to_string();
                            let chal = Challenge::new(cr.src,chalstr.clone());
                            println!("Created challenge: {:?}",chal);
                            let cr2 = cr.clone();
                            let rt  = Runtime::new()?;
                            peers::broadcast(chal.to_msg(),0)?;
                            //thread::spawn(move || {
                                // test by "verifying" ourselves
                                let res = rt.block_on(verify_challenge(cr2,chalstr));
                                if let Err(e) = res {
                                    println!("[verify_challenge] Error from block_on {}",e);
                                }
                            //});
                            //TODO: Fix this api w/ real values + better func
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

async fn https_thread(c_chal_lock: Arc<RwLock<String>>, domain: &str) -> Result<(),std::io::Error> {
    let key = PrivateKeyDer::from(PrivatePkcs1KeyDer::from(db::get_key().private_key_to_der().unwrap()));
    let now = Asn1Time::from_unix(time_now() as i64).unwrap();
    let year_from_now = Asn1Time::from_unix(time_now() as i64 + 31536000).unwrap();
    let mut x509 = X509::builder()?;
    x509.set_version(2)?;
    x509.set_not_before(&now)?;
    x509.set_not_after(&year_from_now)?;
    x509.set_serial_number(&(BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()))?;
    let mut x509_name = X509NameBuilder::new()?;
    // x509_name.append_entry_by_text("C", "CA")?;
    // x509_name.append_entry_by_text("O", "cachain")?;
    x509_name.append_entry_by_text("CN", "cachain-ca")?;
    let x509_name = x509_name.build();
    //TODO: Fix unwrap
    x509.set_issuer_name(&x509_name).unwrap();
    let mut x509_name = X509NameBuilder::new()?;
    // x509_name.append_entry_by_text("C", "CA")?;
    // x509_name.append_entry_by_text("O", "cachain")?;
    x509_name.append_entry_by_text("CN", "cachain")?;
    let x509_name = x509_name.build();
    x509.set_subject_name(&x509_name).unwrap();

    x509.set_pubkey(&PKey::from_rsa(db::get_key()).unwrap());
    x509.sign(&PKey::from_rsa(db::get_key()).unwrap(), openssl::hash::MessageDigest::sha384());

    let x509 = CertificateDer::from(x509.build().to_der().unwrap());
    let mut x509_chain = Vec::new();
    x509_chain.push(x509);
    let config = rustls::ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(x509_chain, key)
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err)).unwrap();

    println!("[https_thread] starting https server listener!!!!");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    let mut challenge_str = String::from("null");
    loop {
        challenge_str = (c_chal_lock.read().unwrap()).clone();
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let fut = async move {
            let mut stream = acceptor.accept(stream).await?;

            let status_line = "HTTP/1.1 200 OK";
            let contents = challenge_str.clone();
            let length = contents.len();
            let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            println!("Hello: {}", peer_addr);
            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("[https_thread]: {:?}", err);
            }
        });
    }
    Ok(()) as io::Result<()>
}

fn setup_https_server_thread(domain: &str, rx: Receiver<String>) -> Result<(),Box<dyn Error>> {
    let chal_lock = Arc::new(RwLock::new(String::from("none")));
    let c_chal_lock = Arc::clone(&chal_lock);
    thread::spawn(move || {
        loop {
            let new_chal = rx.recv().unwrap();
            let mut chal_str = chal_lock.write().unwrap();
            println!("{}", new_chal);
            *chal_str = new_chal;
        }
    });

    let domain = Arc::new(String::from(domain));
    let rt  = Runtime::new()?;
    thread::spawn(move || {
        let res = rt.block_on(https_thread(c_chal_lock, &domain));
        if let Err(e) = res {
            println!("[https_thread] Error from block_on {}",e);
        }
    });
    return Ok(());
}

async fn verify_challenge(req: CertRequest, challenge_str: String) -> io::Result<()> {
    let domain = req.url;
    let content = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", domain);
    let mut root_cert_store = rustls::RootCertStore::empty();
    // wtf do we put in root store
    let mut x509 = X509::builder()?;
    let now = Asn1Time::from_unix(time_now() as i64).unwrap();
    let year_from_now = Asn1Time::from_unix(time_now() as i64 + 31536000).unwrap();
    x509.set_not_before(&now)?;
    x509.set_not_after(&year_from_now)?;
    x509.set_version(2);
    x509.set_serial_number(&(BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()))?;
    let mut x509_name = X509NameBuilder::new()?;
    // x509_name.append_entry_by_text("C", "CA")?;
    // x509_name.append_entry_by_text("O", "cachain")?;
    x509_name.append_entry_by_text("CN", "vchal-ca")?;

    let x509_name = x509_name.build();
    x509.set_issuer_name(&x509_name)?;

    let mut x509_name = X509NameBuilder::new()?;
    // x509_name.append_entry_by_text("C", "CA")?;
    // x509_name.append_entry_by_text("O", "cachain")?;
    x509_name.append_entry_by_text("CN", "vcachain")?;

    let x509_name = x509_name.build();
    x509.set_subject_name(&x509_name)?;

    x509.set_pubkey(&PKey::from_rsa(db::get_key()).unwrap());
    x509.sign(&PKey::from_rsa(db::get_key()).unwrap(), openssl::hash::MessageDigest::sha384());
    let x509 = CertificateDer::from(x509.build().to_der().unwrap());

    root_cert_store.add(x509);

    // root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    println!("[verify_challenge] connecting to {}:8443",domain);
    let stream = tokio::net::TcpStream::connect(format!("{}:8443", domain)).await?;

    let domain = rustls::ServerName::try_from(domain.as_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let mut stream = connector.connect(domain, stream).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    stream.write_all(content.as_bytes()).await?;

    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            ret?;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret?;
            writer.shutdown().await?
        }
    }

    Ok(())
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
    let (tx, rx) = channel::<String>();
    setup_https_server_thread(&domain, rx)?;
    use std::time;
    thread::sleep(time::Duration::from_secs(1));

    // test pipe
    tx.send(String::from("testerov")).unwrap();
    
    if peer == None {
        println!("Creating new genesis from {domain}");
        db::generate_new_genesis(domain);
    } else {
        // Intial chain download
        println!("Intial chain downloading...");
        peers::initial_chain_download();

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
        // spawn a thread to handle the connection
        let ntx = tx.clone();
        thread::spawn(move || {
            let maybe_error = handle_conn(stream, ntx);
            if let Err(e) = maybe_error {
                println!("connection ended with error: {}",e);
            } else {
                println!("connection ended succesfully");
            }
        });
    }
    return Ok(());
}
