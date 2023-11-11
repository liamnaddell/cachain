use openssl::pkey::Public;
use openssl::rsa::Rsa;
use std::error::Error;
use core::result::Result;
use std::net::{SocketAddr, TcpStream};
use std::io::Write;

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
}

pub struct Peers {
    peers: Vec<Peer>,
    peerno: usize,
}

impl Peers {
    //TODO: Guarantee messages are sent to at least one peer and generate peers if there are none
    //returns the number of peers the message was broadcasted to
    pub fn broadcast(&mut self, msg: Vec<u8>, blacklist: u64) -> Result<usize,Box<dyn Error>> {
        let mut i = 0;
        for peer in self.peers.iter_mut()  {
            if peer.addr == blacklist {
                continue;
            }
            peer.send_msg(&msg)?;
            i+=1;
        }
        return Ok(i);
    }
    //TODO: Make this guy reach out to some peers
    pub fn new(peerno: usize) -> Self {
        return Peers{peers:vec!(),peerno:peerno};
    }
}
