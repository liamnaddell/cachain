use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Public,Private};
use crate::msg_capnp::*;
use capnp::*;
use capnp::message::Builder;
use serde::{Deserialize,Serialize};
use std::error::Error;
use core::result::Result;
use crate::chain::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;

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
        let key = deserialize_pubkey(&keytext);
        return Ok(Ping {src:src,dest:dest,key:key,});
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
        let rsa_key = deserialize_pubkey(&keytext);
        let mut peers = vec!();
        for peer in p.get_peers()?.iter() {
            peers.push(peer?.to_string()?);
        }
        return Ok(Pong {src:src,dest:dest,key:rsa_key,peers});
    }
}


#[derive(Debug)]
pub enum AdvertKind {
    CR(chain::CertRequest),      // Cert Request data
    CE(String),                  // Chain Entry hash
    CH(chain::Challenge),        // Challenge hash
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
            advert::kind::Cr(cr) 
                => AdvertKind::CR(chain::CertRequest::from_reader(cr?)?),
            advert::kind::Ce(ce) 
                => AdvertKind::CE(ce?.to_string()?),
            advert::kind::Ch(ch)
                => AdvertKind::CH(chain::Challenge::from_reader(ch?)?)
        };
        return Ok(Advert { src, dest, kind });
    }

    pub fn mint_new_block(dest:u64, hash: &str) -> Self {
        return Advert {src: db::get_addr(), dest: dest, kind: AdvertKind::CE(hash.to_string())};
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
                let mut req_builder = cr.to_builder();
                let cr_builder = req_builder.get_root::<cert_request::Builder>().unwrap();
                kind_builder.set_cr(cr_builder.into_reader())?;
            }
            AdvertKind::CE(ce) => {
                kind_builder.set_ce(text::Reader::from(ce.as_str()));
            }
            AdvertKind::CH(ch) => {
                let mut chal_builder = ch.to_builder();
                let ch_builder = chal_builder.get_root::<challenge::Builder>().unwrap();
                kind_builder.set_ch(ch_builder.into_reader())?;
            }
        };

        let v = serialize::write_message_to_words(&msg_default);
        return Ok(v);
    }
}

#[derive(Debug)]
pub struct Update {
    pub src: u64,
    pub dest: u64,
    pub start_hash: String,
}
impl Update {
    pub fn from_reader(p: update::Reader) -> Result<Self,Box<dyn Error>> {
        let src = p.get_src();
        let dest = p.get_dest();
        let start_hash = p.get_start_hash()?.to_string()?;
        return Ok(Update {src,dest,start_hash});
    }
    pub fn to_capnp(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut message = Builder::new_default();
        let msg_builder = message.init_root::<msg_capnp::msg::Builder>();
        let c_b = msg_builder.init_contents();
        let mut b = c_b.init_update();
        b.set_src(self.src);
        b.set_dest(self.dest);
        b.set_start_hash(text::Reader::from(self.start_hash.as_str()));

        let v = serialize::write_message_to_words(&message);

        return Ok(v);

    }
}

///Gets the current time
use std::time::SystemTime;
pub fn time_now() -> u64 {
    let secs = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    return secs.as_secs();
}

///Serializes a pubkey to pem format
pub fn serialize_pubkey(key: &Rsa<Private>) -> Vec<u8> {
    let to_encode = PKey::from_rsa(key.clone()).unwrap();
    let v = to_encode.public_key_to_pem().unwrap();
    return v;
}

pub fn serialize_pubkey2(key: &Rsa<Public>) -> Vec<u8> {
    let to_encode = PKey::from_rsa(key.clone()).unwrap();
    let v = to_encode.public_key_to_pem().unwrap();
    return v;
}

pub fn deserialize_pubkey(keytext: &str) -> Rsa<Public> {
    let to_encode = PKey::public_key_from_pem(keytext.as_bytes()).unwrap();
    return to_encode.rsa().unwrap();
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

/// Generates an RSA pubkey
pub fn generate() -> Rsa<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    return rsa;
}

/*
pub fn encrypt(rsa: Rsa<Private>) -> Vec<u8> {
    let mut buf = vec![0; rsa.size() as usize];
    let data = b"foobar";
    let _encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    return buf;
}*/

/*pub fn create_update(src: u64, dest:u64, start_msgid: u32, end_msgid:u32) -> Vec<u8> {
    let mut md = Builder::new_default();
    let mut b = md.init_root::<msg_capnp::update::Builder>();
    b.set_src(src);
    b.set_dest(dest);
    b.set_start_hash(text::Reader::from(start_hash.as_str()));
    let v = serialize::write_message_to_words(&md);
    return v;
}*/

pub struct UpdateResponse {
    pub src:u64,
    pub dest:u64,
    pub start_hash: String,             // requested start hash
    pub chain: Vec<chain::ChainEntry>,  // chain entries (maybe the whole chain)
}
use std::fmt;
impl fmt::Display for UpdateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpdateResponse {{ src: {}, dest: {}, start_hash: {}, chain: {{" , self.src,self.dest,self.start_hash)?;
        for ce in self.chain.iter() {
            write!(f,"{}, ",ce)?;
        }
        write!(f,"}} }}")
    }
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
        ur.set_start_hash(text::Reader::from(self.start_hash.as_str()));
        ur.set_dest(self.dest);
        let v = serialize::write_message_to_words(&message);
        return v;
    }
    pub fn from_reader(r: update_response::Reader) -> Result<Self,Box<dyn Error>>  {
        let mut v = vec!();
        let src = r.get_src();
        let dest = r.get_dest();
        let start_hash = r.get_start_hash()?.to_string()?;
        let bchain = r.get_bchain()?;
        for i in 0..bchain.len() {
            let ce_reader = bchain.get(i);
            let ce = chain::ChainEntry::from_reader(ce_reader)?;
            v.push(ce);
        }
        return Ok(UpdateResponse {src,dest,start_hash,chain:v});

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


pub fn x509_sign(private: Rsa<Private>, public: Rsa<Public>, domain: &str) -> String {
    //let key = PrivateKeyDer::from(PrivatePkcs1KeyDer::from(db::get_key().private_key_to_der().unwrap()));
    let now = Asn1Time::from_unix(time_now() as i64).unwrap();
    let year_from_now = Asn1Time::from_unix(time_now() as i64 + 31536000).unwrap();
    let mut x509 = X509::builder().unwrap();
    x509.set_not_before(&now).unwrap();
    x509.set_not_after(&year_from_now).unwrap();
    x509.set_serial_number(&(BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())).unwrap();
    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "CA").unwrap();
    x509_name.append_entry_by_text("O", "cachain").unwrap();
    x509_name.append_entry_by_text("CN", domain).unwrap();
    let x509_name = x509_name.build();
    x509.set_issuer_name(&x509_name).unwrap();
    x509.set_subject_name(&x509_name).unwrap();

    // x509.set_issuer_name("cachain");
    let pubkey_to_sign = PKey::from_rsa(public).unwrap();
    x509.set_pubkey(&pubkey_to_sign).unwrap();
    let privkey_signer = PKey::from_rsa(private).unwrap();
    x509.sign(&privkey_signer, openssl::hash::MessageDigest::md5()).unwrap();
    let x509 = x509.build();

    return String::from_utf8(x509.to_pem().unwrap()).unwrap();

}

use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use openssl::x509::*;

// Use a pubkey to verify the signature of the data signed with the corresponding private key
pub fn verify_signature(public: &Rsa<Public>, data:&Vec<u8> , signature: &Vec<u8>) -> bool {
    let public = PKey::from_rsa(public.clone()).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public).unwrap();
    verifier.update(data.as_slice()).unwrap();
    return verifier.verify(signature).unwrap_or(false);
}

//Signs data using a private rsa key, returns the raw signing data, which can't be trivially
//converted to a string.
pub fn sign(private: Rsa<Private>, data: Vec<u8>) -> Vec<u8> {
    // Generate a keypair
    let keypair = PKey::from_rsa(private).unwrap();

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(&data.as_slice()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    return signature;
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
