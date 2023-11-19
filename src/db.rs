use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Private};
use std::fs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::ops::{Deref,DerefMut};



lazy_static! {
static ref DB_I: Mutex<Option<DB>> = Mutex::new(None);
}

pub struct DB {
    pub chain: Vec<ChainEntry>,
    pub pkey: Rsa<Private>,
    pub addr: u64,
}

use rand::random;
impl DB {
    pub fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey, addr:random()};
    }
    pub fn fast_forward(&mut self, chain: Vec<ChainEntry>) -> bool {
        if self.chain.len() == 0 {
            self.chain=chain;
            return true;
        }
        for new_head in chain.iter() {
            let head = &self.chain[self.chain.len()-1];
            if head.hash == new_head.prev_hash {
                self.chain.push(new_head.clone());
            } else {
                return false;
            }
        }
        return true;
    }

    /// Return the tail of the chain starting from and including the
    /// chain entry with hash `start_hash`.
    /// If `start_hash` is not in the chain, return the whole chain.
    pub fn get_tail(&self, start_hash: &str) -> Vec<ChainEntry> {        
        let mut v = vec!();
        for entry in self.chain.iter().rev() {
            v.insert(0,entry.clone());
            if entry.hash == start_hash {
                break;
            }
        }
        return v;
    }

    /// Return the hash of the last chain entry.
    pub fn get_tip_hash(&self) -> Option<String> {
        if self.chain.len() == 0 {
            return None;
        }
        let head = &self.chain[self.chain.len()-1];
        return Some(head.hash.clone());
    }
}

fn to_disk_db() -> DiskDB {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    let v = serialize_privkey(&db.pkey);
    return DiskDB { chain: db.chain.clone(), pkey:v,addr:db.addr};
}
fn from_disk_db(ddb: DiskDB) {
    let keydata = ddb.pkey;
    let pkey = PKey::private_key_from_pkcs8(&keydata).unwrap();
    let rsa = pkey.rsa().unwrap();
    let mut guard = DB_I.lock().unwrap();
    let option_db = guard.deref_mut();
    let db = DB { chain: ddb.chain, pkey: rsa,addr:ddb.addr};
    *option_db=Some(db);
}

#[derive(Serialize, Deserialize)]
struct DiskDB {
    chain: Vec<ChainEntry>,
    pkey: Vec<u8>,
    addr:u64,
}

//cache commonly required data to avoid lock contention+deadlocks
#[derive(Debug)]
struct StaticInfo {
    pub key: Rsa<Private>,
    pub addr: u64,
}

use std::sync::OnceLock;
static S_DATA: OnceLock<StaticInfo> = OnceLock::new();

use std::path::Path;
//creates DB if it doesn't exist
pub fn load_db(file: &str) {
    if !Path::new(&file).exists() {
        println!("Creating new db");
        let db = DB::new();
        let mut guard = DB_I.lock().unwrap();
        let option_db = guard.deref_mut();
        *option_db=Some(db);
        drop(guard);
        let ddb = to_disk_db();
        fs::write(file,&serde_json::to_string(&ddb).unwrap()).unwrap();
    } else {
        let data = fs::read_to_string(file).unwrap();
        let ddb: DiskDB = serde_json::from_str(&data).unwrap();
        from_disk_db(ddb);
    }
    init_static_data();
}
pub fn init_static_data() {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    let data = StaticInfo {
        key:db.pkey.clone(),
        addr:db.addr,
    };
    S_DATA.set(data).unwrap();
}


pub fn get_key() -> Rsa<Private> {
    let sd = S_DATA.get().unwrap();
    return sd.key.clone();
}

//TODO: This is also stupid, put this data in read-only structure somewhere else with no mutex
pub fn get_addr() -> u64 {
    let sd = S_DATA.get().unwrap();
    return sd.addr;
}

//TODO: THIS IS REALLY DUMB
pub fn get_chain() -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.chain.clone();
}

pub fn find_hash(hash: &str) -> Option<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    for ce in &db.chain {
        if &ce.hash == hash {
            return Some(ce.clone());
        }
    }
    return None;
}

pub fn find_by_domain(domain: &String) -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    let mut v = vec!();
    for ce in &db.chain {
        if &ce.request.url == domain {
            v.push(ce.clone());
        }
    }
    return v;
}

pub fn get_tail(start_hash: &str) -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.get_tail(start_hash);
}

pub fn get_tip_hash() -> Option<String> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.get_tip_hash();
}


//all the info one might need to know about a peer/non-peer
//TODO: merge with Peer struct
pub struct NodeInfo {
    pub url: String,
    pub key: Rsa<Public>,
    pub addr: u64,
}

pub fn current_elector() -> NodeInfo {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    assert!(db.chain.len() != 0);
    let head = &db.chain[db.chain.len()-1];
    let req = &head.request;
    //TODO: Fix this
    let ni = NodeInfo {url:req.url.clone(),key:deserialize_pubkey(req.requester_pubkey.clone()).rsa().unwrap(),addr:0};
    return ni;
}
pub fn fast_forward(v: Vec<ChainEntry>) -> bool {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.fast_forward(v);
}

pub fn generate_new_genesis(url: String) {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");

    //generate key to verify ourselves with
    let verifier_key = generate();

    let our_pubkey = private_to_public(&db.pkey);

    let sigin = x509_sign(verifier_key,our_pubkey);


    let cr = CertRequest::new(url);
    let ce = ChainEntry::new("".to_string(),0,time_now(),sigin.into(),db.pkey.clone(),cr);
    db.chain=vec!(ce);
    
}

//NOTE: Such a function is impossible to write unfortunately, since there are currently no methods
//for transforming the type inside a mutex....
//Haskell would definitely be better here
//but alas
//my weary heart will go on
/*
pub fn db() -> Result<MutexGuard<&mut DB>, Box<dyn Error>> {
    //Mutex Guard
    let mut db_lock = DB_INS.lock()?;
    //&mut Option<T>
    let mut mut_ref_option = db_lock.deref_mut();
    //Option<&mut T>
    let mut option_mut_ref = mut_ref_option.as_deref_mut();
    let mut mut_ref = option_mut_ref.unwrap();
}*/

