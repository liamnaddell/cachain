use openssl::pkey::Public;
use openssl::rsa::Rsa;
use std::error::Error;
use core::result::Result;
use std::net::TcpStream;
use std::io::Write;
use std::collections::{HashSet, VecDeque};
use std::net::ToSocketAddrs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::net::SocketAddr;
use std::thread;
use std::time;

pub fn start_update_thread() {
    println!("[peers] creating the update thread");
    thread::spawn(|| {
        while peer_urls().len() == 0 {
            println!("[peers] cannot start the update thread, no available peers, sleeping until some become available");
            std::thread::sleep(time::Duration::from_secs(100));

        }
        update_thread();
    });
}

///A thread that periodically attempts to get updates from peers
fn update_thread() {
    //Ping+pong n=5 peers
    loop {
        std::thread::sleep(time::Duration::from_secs(10));
        //TODO: In the future, we should xref from mutliple peers
        peers::update_chain("".to_string(),0);
    }
}

const SEEN_QUEUE_SIZE: usize = 420;

///A peer with an optional open TcpStream to the peer used for broadcasting
pub struct Peer {
    pub url: String,
    pub pub_key: Rsa<Public>,
    //cachain address of the peer
    pub addr: u64,
    //ensures only one thread can connect to the Peer at once.
    //NOTE: The peer can initiate a connection TO US at any point, and that connection
    //will not show up here
    conn: Option<TcpStream>,
}

impl Peer {
    pub fn connect(&mut self) -> Result<TcpStream, Box<dyn Error>> {
        //We might already have a connection cached, so we can just use that
        if let Some(conn) = &self.conn {
            return Ok(conn.try_clone()?);
        } else {
            let ts = TcpStream::connect(&self.url)?;
            self.conn=Some((ts).try_clone()?);
            return Ok(ts);
        }
    }
    pub fn send_msg(&mut self, msg: &Vec<u8>) -> Result<(),Box<dyn Error>> {
        let mut ts = self.connect()?;
        ts.write(msg.as_slice())?;
        return Ok(());
    }
    pub fn new(url: String, pub_key: Rsa<Public>,addr:u64) -> Self {
        return Peer {url,pub_key,addr,conn:None};
    }
    ///Constructs a peer using the information received in a Pong
    pub fn from_pong(url: String, p: &Pong) -> Self {
        return Peer::new(url,p.key.clone(),p.src);
    }
    pub fn from_ping(url: String, p: &Ping) -> Self {
        return Peer::new(url,p.key.clone(),p.src);
    }
}

pub struct Peers {
    me: Option<SocketAddr>,
    peers: Vec<Peer>,
    potential_peers: HashSet<String>,
    peerno: usize,
    seen_hashes: VecDeque<String>,
}
//the singleton instance of the Peers struct. Must be intialized using peers::init()
lazy_static! {
static ref PEER_INS: Mutex<Option<Peers>> = Mutex::new(None);
}

use std::ops::DerefMut;

///Broadcasts a message to all the peers except the guy on the blacklist.
/// The blacklist mechanism exists to ensure we don't send advert messages 
/// back to the guy who just sent us the advert.
pub fn broadcast(msg: Vec<u8>, blacklist: u64) -> Result<usize,Box<dyn Error>> {
    let mut guard = PEER_INS.lock()?;
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    peers.broadcast(msg,blacklist)
}

/// Gets a list of urls of the peers we are currently peered with
/// Used to craft Pong responses.
pub fn peer_urls() -> Vec<String> {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");

    let mut v = vec!();
    for peer in peers.peers.iter() {
        v.push(peer.url.clone());
    }
    v
}

///Adds the address (url or ip) to the potential peers list for later use by generate()
pub fn add_potential(paddr: &str) {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");

    peers.potential_peers.insert(paddr.to_string());
}
pub fn add_peer(peer: Peer) {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    peers.peers.push(peer);
}

/// Broadcasts Update messages to peers to update to a given hash. set the hash to "" to get all
/// updates
pub fn update_chain(hash: String, data_src: u64) {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    let _ = peers.update_chain(hash, data_src);
}

/// Intial block download
pub fn initial_chain_download() {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    
    // For now, we will only retrieve the first peer's chain
    // Later implementation may retrieve from multiple peers
    let src_addr = peers.peers.first().unwrap().addr;
    peers.update_chain("".to_string(), src_addr).expect("The initial chain download must succeed");
}

/// Check if a message hash is already been seen
pub fn check_seen_hashes(hash: &String) -> bool {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    return peers.check_seen_hash(&hash);
}

/// Add a new message hash to the seen hashes
pub fn add_seen_hash(hash: String) {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    peers.add_seen_hash(hash);
}

///me is our url, this is used to prevent us from attempting to peer with ourselves (and hanging
///the server binary)
///peer is an optional peer to attempt to reach out to upon initialization (otherwise we fail to
///peer with anyone, and must wait for pings before we can peer)
///peerno is the number of peers to maintain at one time
///The peers subsystem can either be in client or server mode,
///if the peers subsystem is in client mode, it will inform servers that we are a client, and will
/// not enter a mutual relationship.
///The way to specify client mode is by setting `me` to None, indicating we have no domain name.
///Additionally, for client mode, `peer` must be set to a valid peer
pub fn init(me: Option<String>, peer: Option<String>,peerno: usize) {
    {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut();

    let mut peers = Peers::new(me,peer,peerno);

    //attempt to connect with peers
    let peerc = peers.generate();
    //we must peer with at least one other otherwise we just crash
    assert!(peerno == 0 || peerc != 0);
    //complete the initialization
    *option_peer = Some(peers);
    }
}

impl Peers {
    ///returns the number of peers the message was broadcasted to
    pub fn broadcast(&mut self, msg: Vec<u8>, blacklist: u64) -> Result<usize,Box<dyn Error>> {
        let mut i = 0;
        if self.peers.len() == 0 {
            println!("[Peers::broadcast] no peers available, generating more");
            //we have no peers, so we attempt to reach out to more using the potential_peers list
            let newpeers = self.generate();
            assert!(newpeers != 0);
        }
        for peer in self.peers.iter_mut()  {
            //don't broadcast to person on blacklist (usually the guy who just sent us an advert)
            if peer.addr == blacklist {
                continue;
            }
            println!("[peers] broadcasting to {}, blacklisting {}",&peer.url, blacklist);
            peer.send_msg(&msg)?;
            i+=1;
        }
        return Ok(i);
    }
    
    pub fn unicast(&mut self, msg: Vec<u8>, dest: u64) -> Option<&mut Peer> {
        let mut ret = None;
        for peer in self.peers.iter_mut() {
            if peer.addr == dest {
                peer.send_msg(&msg).unwrap();
                ret = Some(peer);
            }
        }
        return ret;
    }
    pub fn update_chain(&mut self, hash: String, src_addr: u64) -> Result<(),Box<dyn Error>> {
        //assert!(self.me != None);
        let data_src = {
            if src_addr == 0 {
                self.peers.first().unwrap().addr
            } else {
                src_addr
            }
        };

        let upd = Update {src: db::get_addr(), dest: data_src,start_hash: hash};
        let msg = upd.to_capnp().unwrap();
        let dest = self.unicast(msg,data_src);
        if let Some(peer) = dest {
            // Read update response from data source
            // can unwrap() here because unicast called send_msg() which opens a connection
            let reader = serialize::read_message(peer.conn.as_ref().unwrap(),capnp::message::ReaderOptions::new())?;
            let msg_reader = reader.get_root::<msg_capnp::update_response::Reader>()?;
            let upd = UpdateResponse::from_reader(msg_reader)?;
            println!("Received update_response from inside peers: {}",upd);
            
            // TODO: need more validation / verification
            if !chain::is_valid_chain(
                &upd.chain,
                upd.start_hash != upd.chain[0].hash
            ) { 
                panic!("Received invalid update :sadge:1");
            }
            let succ = db::merge_compatible(upd.chain);
            if !succ {
                panic!("Cannot add new entries :sadge:2");
            }
        } else {
            panic!("[peers] update_chain: no peer found for data_src {}",data_src);
        } 
        return Ok(());
    }
    pub fn new(me: Option<String>, peer: Option<String>,peerno: usize) -> Self {
        let hs = {
            let mut hs = HashSet::new();
            if let Some(s) = peer {
                hs.insert(s);
            }
            hs
        };
        if let Some(me) = me {
            //we need to figure out our own ip address, that way we don't later attempt to peer with
            //ourselves.
            println!("[peers] resolving own hostname: {}",&me);
            let mut addrs = me.to_socket_addrs().unwrap();
            //this indicates to the user that they don't actually own the domain they are trying to
            //start a server on
            let socket = addrs.next().ok_or("resolution failed").unwrap();
            let seen_hashes: VecDeque<String> = VecDeque::new();
            let peers = Peers {
                me: Some(socket),
                peers:vec!(),
                potential_peers:hs,
                peerno:peerno,
                seen_hashes
            };
            return peers;
        } else {
            //TODO: Not actually used in client mode, fix
            let seen_hashes: VecDeque<String> = VecDeque::new();
            let peers = Peers {
                me: None, 
                peers:vec!(),
                potential_peers:hs,
                peerno:peerno,
                seen_hashes
            };
            return peers;
        }
    }
    pub fn check_seen_hash(&self, hash: &String) -> bool {
        for h in self.seen_hashes.iter() {
            if hash == h {
                return true;
            }
        }
    return false;
    }
    pub fn add_seen_hash(&mut self, hash: String) {
        let length = self.seen_hashes.len();
        if length > SEEN_QUEUE_SIZE {
            self.seen_hashes.pop_front();
        }
        self.seen_hashes.push_back(hash);
    }
    ///This function attempts to enter a peer relation with another node in the potential_peers
    ///list
    pub fn generate_peer(&mut self) -> Result<(),Box<dyn Error>> {
        //get the url from the potential_peers list
        let url:String = {
            if self.potential_peers.len() == 0 {
                return Err("[generate_peer] exhausted the potential_peers list".into());
            } else {
                let peer = self.potential_peers.iter().next().expect("there's at least 1 peer, but no next element").clone();
                self.potential_peers.remove(&peer);
                peer+":8069"
            }
        };
        println!("[peers] resolving {}",url);
        //perform dns resolution to get the IP address
        let addrs = url.to_socket_addrs();
        let mut socket = addrs?.next().ok_or("resolution failed")?;
        socket.set_port(8069);
        println!("Attempting to enter peership with {:?}",socket);


        //check that we don't try to peer to ourselves
        if Some(socket) == self.me {
            return Err(Box::<dyn Error + Send + Sync>::from("Not peering to self"));
        }

        //intitialize connection and send ping
        let mut stream = TcpStream::connect(socket)?;
        let ping = {
            Ping {src:db::get_addr(),dest:0,key:private_to_public(&db::get_key())}
        };
        let msg_ping = ping.to_msg()?;
        stream.write(&msg_ping)?;

        //read pong to get information back.
        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();
        let pong_msg = reader.get_root::<msg_capnp::pong::Reader>().unwrap();
        let pong = Pong::from_reader(pong_msg)?;
        //handshake has completed :)
        println!("[peers] Entered peership with {}",&url);
        //We store the IP address in the peers struct instead of the url. If you need the URL, you
        //can use the blockchain to get it by searching-by-addr. This can be re-designed later.
        let sa = format!("{:?}",socket);
        let peer = Peer::from_pong(sa,&pong);
        self.peers.push(peer);
        //loop through our new peer's list of peers, and add them to the potential list in case we
        //need to add more peers later.
        for pong_peer in pong.peers.iter() {
            let mut already_peered_w = false;
            for current_peer in &self.peers {
                if &current_peer.url == pong_peer {
                    already_peered_w = true;
                    break;
                }
            }
            if already_peered_w {
                continue;
            }
            self.potential_peers.insert(pong_peer.clone());
        }
        return Ok(());
    }

    ///attempt to generate peerno peers by performing handshakes
    pub fn generate(&mut self) -> usize {
        let mut count = 0;
        for _ in 0..self.peerno {
            let result = self.generate_peer();
            if let Err(e) = result { 
                println!("[peers] Generation failed: {}", e)
            } else {
                count+=1;
            } 
        }
        return count;
    }
}
