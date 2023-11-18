use openssl::rsa::{Rsa,Padding};
use openssl::pkey::{PKey,Public,Private};
use crate::msg_capnp::*;
use capnp::*;
use capnp::message::Builder;
use serde::{Deserialize,Serialize};
use std::error::Error;
use core::result::Result;
use crate::chain::*;

pub mod peers;
pub mod db;
pub mod chain;

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
pub enum AdvertKind {
    CR(String),
    CE(String),
}

#[derive(Debug)]
pub struct Advert {
    pub src: u64,
    pub dest: u64,
    pub kind: AdvertKind,
}
impl Advert {
    pub fn from_reader(p: advert::Reader) -> Result<Self, Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let kind: AdvertKind = match p.get_kind().which()? {
            advert::kind::Cr(cr) => AdvertKind::CR(cr?.to_string()?),
            advert::kind::Ce(ce) => AdvertKind::CE(ce?.to_string()?),
        };
        return Ok(Advert { src, dest, kind });
    }

    pub fn to_msg(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut msg_default = Builder::new_default();
        let msg_builder = msg_default.init_root::<msg_capnp::msg::Builder>();
        let c_builder = msg_builder.init_contents();
        let mut ad_builder = c_builder.init_advert();
        ad_builder.set_src(self.src);
        ad_builder.set_dest(self.dest);
        let mut kind_builder = ad_builder.init_kind();
        match &self.kind {
            AdvertKind::CR(cr) => {
                kind_builder.set_cr(text::Reader::from(cr.as_str()));
            }
            AdvertKind::CE(ce) => {
                kind_builder.set_ce(text::Reader::from(ce.as_str()));
            }
        };

        let v = serialize::write_message_to_words(&msg_default);
        return Ok(v);
    }
}


#[derive(Debug)]
pub struct GetRequest {
    pub src: u64,
    pub dest: u64,
    pub req_hash: String,
}
impl GetRequest {
    pub fn from_reader(p: get_request::Reader) -> Result<Self, Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let req_hash = p.get_req_hash()?.to_string()?;
        return Ok(GetRequest { src, dest, req_hash });
    }

    pub fn to_msg(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut msg_default = Builder::new_default();
        let msg_builder = msg_default.init_root::<msg_capnp::msg::Builder>();
        let c_builder = msg_builder.init_contents();
        let mut gr_builder = c_builder.init_get_request();
        gr_builder.set_src(self.src);
        gr_builder.set_dest(self.dest);
        gr_builder.set_req_hash(text::Reader::from(self.req_hash.as_str()));

        let v = serialize::write_message_to_words(&msg_default);
        return Ok(v);
    }
}

pub struct RequestData {
    pub src: u64,
    pub dest: u64,
    pub req_data: chain::CertRequest,
}
impl RequestData {
    pub fn to_msg(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut default = Builder::new_default();
        let msg_builder = default.init_root::<msg_capnp::msg::Builder>();
        let c_builder = msg_builder.init_contents();
        let mut rd_builder = c_builder.init_request_data();
        
        rd_builder.set_src(self.src);
        rd_builder.set_dest(self.dest);
        
        let mut req_builder = self.req_data.to_builder();
        let req_root_builder = req_builder.get_root::<cert_request::Builder>().unwrap();
        rd_builder.set_req_data(req_root_builder.into_reader())?;

        let v = serialize::write_message_to_words(&default);
        return Ok(v);
    }

    pub fn from_reader(reader: request_data::Reader) -> Result<Self, Box<dyn Error>> {
        let src = reader.get_src();
        let dest = reader.get_dest();
        let req_data = reader.get_req_data()?;
        let req = chain::CertRequest::from_reader(req_data)?;
        return Ok(RequestData { src, dest, req_data: req });
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
        let msg_builder = message.init_root::<msg_capnp::msg::Builder>();
        let c_b = msg_builder.init_contents();
        let mut b = c_b.init_update();
        b.set_src(self.src);
        b.set_dest(self.dest);
        b.set_start_msgid(self.start_msgid);
        b.set_end_msgid(self.end_msgid);

        let v = serialize::write_message_to_words(&message);

        return Ok(v);

    }
}

pub struct ChainData {
    pub src: u64,
    pub dest: u64,
    pub req_start: String,
    pub chain_data: Vec<chain::ChainEntry>,
}
// TODO: add implementation for creating message and extracting chain data


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

/*pub fn create_update(src: u64, dest:u64, start_msgid: u32, end_msgid:u32) -> Vec<u8> {
    let mut md = Builder::new_default();
    let mut b = md.init_root::<msg_capnp::update::Builder>();
    b.set_src(src);
    b.set_dest(dest);
    b.set_start_msgid(start_msgid);
    b.set_end_msgid(end_msgid);
    let v = serialize::write_message_to_words(&md);
    return v;
}*/

pub struct UpdateResponse {
    pub src:u64,
    pub dest:u64,
    pub chain: Vec<chain::ChainEntry>,
}

impl UpdateResponse {
    pub fn to_capnp(&self) -> Vec<u8> {
        let mut message = Builder::new_default();
        let mut ur = message.init_root::<msg_capnp::update_response::Builder>();
        let mut b2 = ur.reborrow().init_bchain(self.chain.len() as u32);
        let mut i:u32 = 0;
        for ce in self.chain.iter() {
            let mut ceb = ce.to_builder();
            let ce_builder = ceb.get_root::<chain_entry::Builder>().unwrap();
            b2.set_with_caveats(i,ce_builder.into_reader()).unwrap();
            i+=1;
        }
        ur.reborrow().set_src(self.src);
        ur.set_dest(self.dest);
        let v = serialize::write_message_to_words(&message);
        return v;
    }
    pub fn from_reader(r: update_response::Reader) -> Result<Self,Box<dyn Error>>  {
        let mut v = vec!();
        let src = r.get_src();
        let dest = r.get_dest();
        let bchain = r.get_bchain()?;
        for i in 0..bchain.len() {
            let ce_reader = bchain.get(i);
            let ce = ChainEntry::from_reader(ce_reader)?;
            v.push(ce);
        }
        return Ok(UpdateResponse {src,dest,chain:v});

    }
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
