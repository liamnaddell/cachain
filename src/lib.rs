use openssl::rsa::{Rsa,Padding};
use openssl::pkey::Private;
use openssl::x509::X509ReqBuilder;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::X509Req;
use crate::msg_capnp::ping;
use capnp::*;
use capnp::message::Builder;
use serde::{Deserialize,Serialize};
use std::fs;

#[derive(Serialize, Deserialize,Clone)]
struct ChainEntry {
    url: String,
    website_pubkey: String,
    verifer_signature: String,
    msgid: u64,
    msg_signature: String,
}

pub struct DB {
    chain: Vec<ChainEntry>,
    pkey: Rsa<Private>,
}

impl DB {
    fn to_disk_db(&self) -> DiskDB {
        let to_encode = PKey::from_rsa(self.pkey.clone()).unwrap();
        let v = to_encode.private_key_to_pkcs8().unwrap();
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
        fs::write(file,&serde_json::to_string(&ddb).unwrap());
        return db;
    } else {
        let data = fs::read_to_string(file).unwrap();
        let ddb: DiskDB = serde_json::from_str(&data).unwrap();
        return DB::from_disk_db(ddb);
    }
}


pub fn add(left: usize, right: usize) -> usize {
    left + right
}
pub fn generate() -> Rsa<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    return rsa;
}
pub fn encrypt(rsa: Rsa<Private>) -> Vec<u8> {
    let mut buf = vec![0; rsa.size() as usize];
    let data = b"foobar";
    let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    return buf;
}

pub fn create_ping(src: u64, dest: u64) -> Vec<u8> {
    let mut md = Builder::new_default();
    let mut b = md.init_root::<msg_capnp::ping::Builder>();
    b.set_src(src);
    b.set_dest(dest);
    let v = serialize::write_message_to_words(&md);
    return v;
}

pub fn create_pong(src: u64, dest: u64) -> Vec<u8> {
    let mut md = Builder::new_default();
    let mut b = md.init_root::<msg_capnp::pong::Builder>();
    b.set_src(src);
    b.set_dest(dest);
    let v = serialize::write_message_to_words(&md);
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
