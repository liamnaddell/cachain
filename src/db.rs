use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Private};
use std::fs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::ops::{Deref,DerefMut};
use std::cmp::min;



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
    ///Generates a new db with a new pkey and a random address
    pub fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey, addr:random()};
    }
    ///Appends chain to our chain, returning false if the chains are incompatible
    ///Chains are incompatable when the prev_hash and previous node's hash do not match. 
    ///A more complicated algorithm is required to be implemnented,
    ///See functional requirements for more info.
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
    ///If we have two chains:
    ///  A->B->C->D
    ///        C->D->E->F
    ///Produce the following chain:
    ///  A->B->C->D->E->F
    pub fn merge_compatible(&mut self, chain: Vec<ChainEntry>) -> bool {
        assert!(self.chain.len() != 0);
        let mut max = min(chain.len(),self.chain.len());
        let them = chain[0].hash;
        //iterate through to first shared entry
        let mut i = 0;
        //beginning index where these chains share an entry
        let mut begindex: isize =-1;
        for us in self.chain.iter() {
            if us.hash == them {
                begindex=i;
                break;
            }
            i+=1;
        }
        //these chains have no common entries, incompatible
        if begindex == -1 {
            return false;
        }
        let mut begindex = begindex as usize;
        //skip common entries so we can fast-forward
        let mut usindex=begindex;
        let mut themindex=0;
        while self.chain[usindex].hash == chain[themindex].hash {
            usindex+=1;
            themindex+=1;
            if themindex == max {
                //the incoming chain is a subset of our current chain, no FF required
                return true;
            }
        }
        self.fast_forward(chain[themindex..].to_vec())
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
    /// Returns None if there is no chain yet.
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

///A version of the database that can be serialized to disk.
#[derive(Serialize, Deserialize)]
struct DiskDB {
    chain: Vec<ChainEntry>,
    pkey: Vec<u8>,
    addr:u64,
}

///cache commonly required data to avoid lock contention+deadlocks
#[derive(Debug)]
struct StaticInfo {
    pub key: Rsa<Private>,
    pub addr: u64,
}

//static variable that can only be written to once. This code is used to store our private key and
//our network address.
use std::sync::OnceLock;
static S_DATA: OnceLock<StaticInfo> = OnceLock::new();

use std::path::Path;
///Loads database from file, otherwise creates a new database using DB::new()
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

//Initializes static data, called by load_db
fn init_static_data() {
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

pub fn get_addr() -> u64 {
    let sd = S_DATA.get().unwrap();
    return sd.addr;
}

pub fn get_chain() -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.chain.clone();
}

///Find block matching hash in database, returns None if no ChainEntry is found.
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

/// Find all chain entries with url field `domain`
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

///get the tail of the chain starting at start_hash, returns empty if start_hash is invalid
pub fn get_tail(start_hash: &str) -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.get_tail(start_hash);
}

///Returns tail of chain (unless chain is empty)
pub fn get_tip_hash() -> Option<String> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.get_tip_hash();
}


//all the info one might need to know about a peer/non-peer
pub struct NodeInfo {
    pub url: String,
    pub key: Rsa<Public>,
    pub addr: u64,
}

/// Reads the chain to determine who is the verifer for an incoming ChainEntry.
pub fn current_elector() -> NodeInfo {
    adskjfalkdsfjkl
    //TOOD: premote based off of senority, handle unresponsive verifier/mutliple cert requests
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    //shouldn't call current_elector on an empty chain (doy)
    assert!(db.chain.len() != 0);

    let tiph = db.get_tip_hash().unwrap();
    let randint: usize = tiph.as_bytes().iter().fold(0,|acc,y| acc+(*y as usize));
    let chainlen = db.chain.len();
    //yes, this isn't evenly distributed, no it doesn't matter.
    let entryno = randint % chainlen;
    let entry = &db.chain[entryno];
    let req = &entry.request;
    let ni = NodeInfo {url:req.url.clone(),key:deserialize_pubkey(&req.requester_pubkey),addr:req.src};
    return ni;
}

/// Add ChainEntries to the blockchain, returning false if the incoming ChainEntries are
/// incompatible with the existing chain.
pub fn fast_forward(v: Vec<ChainEntry>) -> bool {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.fast_forward(v);
}
pub fn merge_compatible(chain: Vec<ChainEntry>) -> bool {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.merge_compatible(chain);
}

///Generates a new genesis block with our info and url as the root of the blockchain.
///Self-signs our URL+key using a key who's info is thrown out when the function exits.
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

