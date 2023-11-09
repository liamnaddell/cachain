use openssl::rsa::{Rsa,Padding};
use openssl::pkey::Private;
use openssl::pkey::PKey;
use crate::msg_capnp::*;
use capnp::*;
use capnp::message::Builder;
use serde::{Deserialize,Serialize};
use std::fs;
use openssl::pkey::Public;
use std::error::Error;
use core::result::Result;

mod ecs;

mod chain;

#[derive(Serialize, Deserialize,Clone)]
pub struct ChainEntry {
    pub url: String,
    pub website_pubkey: String,
    pub verifier_signature: String,
    pub msgid: u64,
    pub msg_signature: String,
}

impl ChainEntry {
    pub fn to_builder(&self) ->  capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut mb = Builder::new_default();

        let mut ce = mb.init_root::<msg_capnp::chain_entry::Builder>();

        ce.set_url(text::Reader::from(self.url.as_str()));
        ce.set_verifier_sig(text::Reader::from(self.verifier_signature.as_str()));
        ce.set_msgid(self.msgid);
        ce.set_msg_sig(text::Reader::from(self.msg_signature.as_str()));
        return mb;
        

    }

}

#[derive(Debug)]
pub struct Ping {
    pub src: u64,
    pub dest: u64,
    pub key: Rsa<Public>,
}
impl Ping {
    pub fn from_reader(p: ping::Reader) -> Result<Self,Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let keytext = p.get_key()?.to_string()?;
        let key = deserialize_pubkey(keytext);
        let rsa_key = key.rsa()?;
        return Ok(Ping {src:src,dest:dest,key:rsa_key,});
    }
    pub fn to_msg(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut md = Builder::new_default();
        let mut b = md.init_root::<msg_capnp::ping::Builder>();
        let keytext = serialize_pubkey2(&self.key);
        b.set_src(self.src);
        b.set_dest(self.dest);
        let keyreader = text::Reader::from(keytext.as_slice());
        b.set_key(keyreader);

        let mut md2 = Builder::new_default();
        let b2 = md2.init_root::<msg_capnp::msg::Builder>();
        let mut contents_builder = b2.init_contents();
        contents_builder.set_ping(b.into_reader())?;
        let v = serialize::write_message_to_words(&md2);

        return Ok(v);

    }
}

#[derive(Debug)]
pub struct Pong {
    pub src: u64,
    pub dest: u64,
    pub key: Rsa<Public>,
    pub peers: Vec<String>,
}
impl Pong {
    pub fn from_reader(p: pong::Reader) -> Result<Self,Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let keytext = p.get_key()?.to_string()?;
        let key = deserialize_pubkey(keytext);
        let rsa_key = key.rsa()?;
        let mut peers = vec!();
        for peer in p.get_peers()?.iter() {
            peers.push(peer?.to_string()?);
        }
        return Ok(Pong {src:src,dest:dest,key:rsa_key,peers});
    }
}

#[derive(Debug)]
pub struct Update {
    pub src: u64,
    pub dest: u64,
    pub start_msgid: u32,
    pub end_msgid: u32,
}
impl Update {
    pub fn from_reader(p: update::Reader) -> Result<Self,Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let start_msgid=p.get_start_msgid();
        let end_msgid=p.get_end_msgid();
        return Ok(Update {src:src,dest:dest,start_msgid,end_msgid});
    }
    pub fn to_capnp(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut message = Builder::new_default();
        let mut msg_builder = message.init_root::<msg_capnp::msg::Builder>();
        let mut c_b = msg_builder.init_contents();
        let mut b = c_b.init_update();
        b.set_src(self.src);
        b.set_dest(self.dest);
        b.set_start_msgid(self.start_msgid);
        b.set_end_msgid(self.end_msgid);

        let v = serialize::write_message_to_words(&message);

        return Ok(v);

    }
}


pub struct DB {
    pub chain: Vec<ChainEntry>,
    pub pkey: Rsa<Private>,
}

impl DB {
    fn to_disk_db(&self) -> DiskDB {
        let v = serialize_privkey(&self.pkey);
        return DiskDB { chain: self.chain.clone(), pkey:v};
    }
    fn from_disk_db(ddb: DiskDB) -> DB {
        let keydata = ddb.pkey;
        let pkey = PKey::private_key_from_pkcs8(&keydata).unwrap();
        let rsa = pkey.rsa().unwrap();
        return DB { chain: ddb.chain, pkey: rsa};

    }
    fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey};
    }
}

pub fn serialize_pubkey(key: &Rsa<Private>) -> Vec<u8> {
    let to_encode = PKey::from_rsa(key.clone()).unwrap();
    let v = to_encode.public_key_to_pem().unwrap();
    return v;
}

//TODO: fix this stupid
pub fn serialize_pubkey2(key: &Rsa<Public>) -> Vec<u8> {
    let to_encode = PKey::from_rsa(key.clone()).unwrap();
    let v = to_encode.public_key_to_pem().unwrap();
    return v;
}

pub fn deserialize_pubkey(keytext: String) -> PKey<Public> {
    let to_encode = PKey::public_key_from_pem(keytext.as_bytes()).unwrap();
    return to_encode;
}

pub fn serialize_privkey(key: &Rsa<Private>) -> Vec<u8> {
    let to_encode = PKey::from_rsa(key.clone()).unwrap();
    let v = to_encode.private_key_to_pkcs8().unwrap();
    return v;
}

pub fn private_to_public(key: &Rsa<Private>) -> Rsa<Public> {
    let pubkey = Rsa::from_public_components(key.n().to_owned().unwrap(),key.e().to_owned().unwrap()).unwrap();
    return pubkey;
}

#[derive(Serialize, Deserialize)]
struct DiskDB {
    chain: Vec<ChainEntry>,
    pkey: Vec<u8>,
}

use std::path::Path;
//creates DB if it doesn't exist
pub fn load_db(file: &str) -> DB {
    if ! Path::new(&file).exists() {
        println!("Creating new db");
        let db = DB::new();
        let ddb = db.to_disk_db();
        fs::write(file,&serde_json::to_string(&ddb).unwrap()).unwrap();
        return db;
    } else {
        let data = fs::read_to_string(file).unwrap();
        let ddb: DiskDB = serde_json::from_str(&data).unwrap();
        return DB::from_disk_db(ddb);
    }
}

pub fn generate() -> Rsa<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    return rsa;
}

pub fn encrypt(rsa: Rsa<Private>) -> Vec<u8> {
    let mut buf = vec![0; rsa.size() as usize];
    let data = b"foobar";
    let _encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    return buf;
}

pub fn create_update(src: u64, dest:u64, start_msgid: u32, end_msgid:u32) -> Vec<u8> {
    let mut md = Builder::new_default();
    let mut b = md.init_root::<msg_capnp::update::Builder>();
    b.set_src(src);
    b.set_dest(dest);
    b.set_start_msgid(start_msgid);
    b.set_end_msgid(end_msgid);
    let v = serialize::write_message_to_words(&md);
    return v;
}

pub fn create_update_response(src: u64, dest:u64, chain: Vec<ChainEntry>) -> Vec<u8> {
    let mut message = Builder::new_default();
    let mut ur = message.init_root::<msg_capnp::update_response::Builder>();
    let mut b2 = ur.reborrow().init_bchain(chain.len() as u32);
    let mut i:u32 = 0;
    for ce in chain.iter() {
        let mut ceb = ce.to_builder();
        let ce_builder = ceb.get_root::<chain_entry::Builder>().unwrap();
        b2.set_with_caveats(i,ce_builder.into_reader()).unwrap();
        i+=1;
    }
    ur.reborrow().set_src(src);
    ur.set_dest(dest);
    let v = serialize::write_message_to_words(&message);
    return v;
}

pub fn create_pong(src: u64, dest: u64,key: &Rsa<Private>, peers: Vec<String>) -> Vec<u8> {
    let mut message = Builder::new_default();
    let mut pong = message.init_root::<msg_capnp::pong::Builder>();
    let keydata = serialize_pubkey(key);
    pong.set_src(src);
    pong.set_dest(dest);
    let mut key = pong.reborrow().init_key(keydata.len() as u32);
    key.push_str(&String::from_utf8(keydata).unwrap());
    let mut peer_builder = pong.init_peers(peers.len() as u32);
    for i in 0..peers.len() {
        peer_builder.reborrow().set(i as u32,capnp::text::Reader::from(peers[i].as_str()));
    }
    let v = serialize::write_message_to_words(&message);
    return v;
}

pub mod msg_capnp {
    include!(concat!(env!("OUT_DIR"), "/msg_capnp.rs"));
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x509_demo() {
        let verifier_rsa: Rsa<Private> = generate();
        let verifier_pkey = PKey::from_rsa(verifier_rsa).unwrap();
        //an x509 request is the certificate of the CA
        let mut req_builder: X509ReqBuilder = X509ReqBuilder::new().unwrap();
        req_builder.set_pubkey(&verifier_pkey);
        let verifier_req: X509Req = req_builder.build();
        //use to_pem to serialize

        //Now we are going to use verifier_req to sign a certificate
        let verified_rsa = generate();
        let verified_pkey = PKey::from_rsa(verified_rsa).unwrap();
        let mut other_builder = X509ReqBuilder::new().unwrap();
        other_builder.set_pubkey(&verified_pkey);
        other_builder.sign(&verifier_pkey,MessageDigest::sha384()).unwrap();
        let verified_req: X509Req = other_builder.build();
    }
    use openssl::sign::{Signer, Verifier};
    use openssl::rsa::Rsa;
    use openssl::pkey::PKey;
    use openssl::hash::MessageDigest;
    #[test]
    fn sign_demo() {
        
        // Generate a keypair
        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();

        let data = b"hello, world!";
        let data2 = b"hola, mundo!";

        // Sign the data
        let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let signature = signer.sign_to_vec().unwrap();

        // Verify the data
        let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
        verifier.update(data).unwrap();
        verifier.update(data2).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
