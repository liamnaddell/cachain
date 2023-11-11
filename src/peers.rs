use openssl::pkey::Public;
use openssl::rsa::Rsa;
use std::error::Error;
use core::result::Result;
use std::net::TcpStream;
use std::io::Write;
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;

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
    pub fn from_pong(url: String, p: &Pong) -> Self {
        return Peer::new(url,p.key.clone(),p.src);
    }
}

pub struct Peers {
    peers: Vec<Peer>,
    potential_peers: HashSet<String>,
    peerno: usize,
}
lazy_static! {
//static ref peer_instance: Mutex<Option<Peers>> = Mutex::new(RefCell::new(None));
static ref PEER_INS: Mutex<Option<Peers>> = Mutex::new(None);
}

use std::ops::DerefMut;

pub fn broadcast(msg: Vec<u8>, blacklist: u64) -> Result<usize,Box<dyn Error>> {
    let mut guard = PEER_INS.lock()?;
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    peers.broadcast(msg,blacklist)
}

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
pub fn add_potential(paddr: &str) {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut().as_mut();
    let peers: &mut Peers = option_peer.expect("shouldn't be none");
    peers.potential_peers.insert(paddr.to_string());
}

pub fn init(peer: Option<String>,peerno: usize) {
    {
    let mut guard = PEER_INS.lock().unwrap();
    let option_peer = guard.deref_mut();
    let mut peers = Peers::new(peer,peerno);
    let peerc = peers.generate();
    assert!(peerno == 0 || peerc != 0);
    *option_peer = Some(peers);
    }
}

impl Peers {
    //TODO: Guarantee messages are sent to at least one peer and generate peers if there are none
    //returns the number of peers the message was broadcasted to
    pub fn broadcast(&mut self, msg: Vec<u8>, blacklist: u64) -> Result<usize,Box<dyn Error>> {
        let mut i = 0;
        if self.peers.len() == 0 {
            println!("[Peers::broadcast] no peers available, generating more");
            let newpeers = self.generate();
            assert!(newpeers != 0);
        }
        for peer in self.peers.iter_mut()  {
            if peer.addr == blacklist {
                continue;
            }
            peer.send_msg(&msg)?;
            i+=1;
        }
        return Ok(i);
    }
    pub fn new(peer: Option<String>,peerno: usize) -> Self {
        let hs = {
            let mut hs = HashSet::new();
            if let Some(s) = peer {
                hs.insert(s);
            }
            hs
        };
        let peers  = Peers{peers:vec!(),potential_peers:hs,peerno:peerno};
        return peers;
    }
    pub fn generate_peer(&mut self) -> Result<(),Box<dyn Error>> {
        let url:String = {
            if self.potential_peers.len() == 0 {
                println!("[generate_peer] exhausted the potential_peers list");
                return Ok(());
            } else {
                let peer = self.potential_peers.iter().next().expect("there's at least 1 peer, but no next element").clone();
                self.potential_peers.remove(&peer);
                peer
            }
        };
        println!("Attepting to enter peership with {url}");
        let addrs = url.to_socket_addrs();
        let mut socket = addrs?.next().ok_or("resolution failed")?;
        socket.set_port(8069);
        let mut stream = TcpStream::connect(socket)?;
        let ping = {
            Ping {src:db::get_addr(),dest:0,key:private_to_public(&db::get_key())}
        };
        let msg_ping = ping.to_msg()?;

        stream.write(&msg_ping)?;
        let reader = serialize::read_message(&stream,capnp::message::ReaderOptions::new()).unwrap();
        let pong_msg = reader.get_root::<msg_capnp::pong::Reader>().unwrap();
        let pong = Pong::from_reader(pong_msg)?;
        println!("[peers] Entered peership with {}",&url);
        let peer = Peer::from_pong(url,&pong);
        self.peers.push(peer);
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
    pub fn generate(&mut self) -> usize {
        let mut count = 0;
        for _ in 0..self.peerno {
            let result = self.generate_peer();
            if result.is_ok() {
                count+=1;
            }
        }
        return count;
    }
}
