use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Private};
use std::fs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::ops::{Deref,DerefMut};
use std::sync::mpsc::{Sender,Receiver,channel};



lazy_static! {
static ref DB_I: Mutex<Option<DB>> = Mutex::new(None);
}

pub struct DB {
    pub chain: Vec<ChainEntry>,
    pub pkey: Rsa<Private>,
    pub addr: u64,
    //transmitter for updates to the blockchain
    tx: Option<Sender<ChainEntry>>,
    in_memory: bool,

}

use rand::random;
impl DB {
    ///Generates a new db with a new pkey and a random address
    pub fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey, addr:random(), tx: None, in_memory: true};
    }
    fn add_block(&mut self, ce: ChainEntry) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(ce.clone());
        }
        self.chain.push(ce);
        self.write_db().unwrap();
    }
    fn write_db(&self) -> Result<(),Box<dyn Error>> {
        if db_in_memory() {
            return Ok(());
        }
        let ddb = self.to_disk_db();
        fs::write("server_db.json",&serde_json::to_string(&ddb)?)?;
        return Ok(());
    }
    ///Appends chain to our chain, returning false if the chains are incompatible
    ///Chains are incompatable when the prev_hash and previous node's hash do not match. 
    ///If `verify` is true, perform verification on each new entry before adding it to the chain.
    ///If verification fails, return false but still add preivous entries to the chain.
    pub fn fast_forward(&mut self, chain: Vec<ChainEntry>, verify: bool) -> bool {
        if self.chain.len() == 0 {
            for b in chain.iter() {
                self.add_block(b.clone());
            }
            return true;
        }
        for new_head in chain.iter() {
            let head_pos = self.chain.len()-1;
            if verify && !chain::verify_entry(&self.chain, new_head, head_pos) {
                return false;
            }
            else {
                self.add_block(new_head.clone());
            }
        }
        return true;
    }
    pub fn get_elector_seed(&self, cr: &CertRequest,pos:usize) -> u64 {
        let tiph = &self.chain[pos].hash;
        let randint = tiph.as_bytes().iter().fold(0,|acc,y| acc+(*y as u64)) 
            + cr.created_time;
        return randint;

    }
    ///If we have two chains:
    ///  A->B->C->D
    ///        C->D->E->F
    ///Produce the following chain:
    ///  A->B->C->D->E->F
    pub fn merge_compatible(&mut self, chain: Vec<ChainEntry>) -> bool {
        if self.chain.len() == 0 {
            self.fast_forward(chain, false);
            return true;
        }
        let them = &chain[0].hash;
        //iterate through to first shared entry
        let mut i = 0;
        //beginning index where these chains share an entry
        let mut begindex: isize =-1;
        for us in self.chain.iter() {
            if &us.hash == them {
                begindex=i;
                break;
            }
            i+=1;
        }
        //these chains have no common entries, incompatible
        if begindex == -1 {
            return false;
        }
        let begindex = begindex as usize;
        //skip common entries so we can fast-forward
        let mut usindex=begindex;
        let mut themindex=0;
        while (usindex < self.chain.len()) && (themindex < chain.len()) && 
            (self.chain[usindex].hash == chain[themindex].hash) {
            usindex+=1;
            themindex+=1;
        }
        self.fast_forward(chain[themindex..].to_vec(), true)
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
    //returns a channel that updates to the chain are sent on
    pub fn update_channel(&mut self) -> Receiver<ChainEntry> {
        let (tx,rx) = channel();
        self.tx=Some(tx);
        return rx;
    }

    fn to_disk_db(&self) -> DiskDB {
        let v = serialize_privkey(&self.pkey);
        return DiskDB { chain: self.chain.clone(), pkey:v,addr:self.addr};
    }
    
    /// Returns the hash of the genesis block
    pub fn get_genesis_hash(&self) -> Option<String> {
        if self.chain.len() == 0 {
            return None;
        }
        let head = &self.chain[0];
        return Some(head.hash.clone());
    }

    /// Compare the local chain to a remote chain, and return the last common index.
    pub fn last_common_index(&self, remote: &Vec<ChainEntry>) -> Option<usize> {
        for (i, entry) in remote.iter().enumerate() {
            if i >= self.chain.len() {
                return Some(i-1);
            }
            if entry.hash != self.chain[i].hash {
                if i == 0 {
                    return None;
                } else {
                    return Some(i-1);
                }
            }
        }
        return Some(remote.len()-1);
    }

    /// Replace entries after position `after` with `new_entries`.
    /// If `after` is not in the chain, do nothing.
    pub fn replace(&mut self, after: usize, new_entries: &[ChainEntry]) {
        if after >= self.chain.len() {
            return;
        }
        self.chain.truncate(after + 1);
        for entry in new_entries {
            self.chain.push(entry.clone());
        }
    }
}

fn to_disk_db() -> DiskDB {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.to_disk_db();
}

fn from_disk_db(ddb: DiskDB) {
    let keydata = ddb.pkey;
    let pkey = PKey::private_key_from_pkcs8(&keydata).unwrap();
    let rsa = pkey.rsa().unwrap();
    let mut guard = DB_I.lock().unwrap();
    let option_db = guard.deref_mut();
    assert!(ddb.chain.len() > 0);
    let db = DB { chain: ddb.chain, pkey: rsa,addr:ddb.addr, tx: None, in_memory: false};
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
    pub in_memory: bool,
}

//static variable that can only be written to once. This code is used to store our private key and
//our network address.
use std::sync::OnceLock;
static S_DATA: OnceLock<StaticInfo> = OnceLock::new();

use std::path::Path;
///Loads database from file, otherwise creates a new database using DB::new()
pub fn load_db(file: &str, url: Option<&str>) {
    if !Path::new(&file).exists() {
        println!("[db] creating a new db");
        let mut db = DB::new();
        db.in_memory=false;
        let mut guard = DB_I.lock().unwrap();
        let option_db = guard.deref_mut();
        *option_db=Some(db);
        drop(guard);
        init_static_data();
        if url != None {
            generate_new_genesis(url.unwrap().to_string());
            write_db().unwrap();
        }
    } else {
        println!("[db] reading db from {}",file);
        let data = fs::read_to_string(file).unwrap();
        let ddb: DiskDB = serde_json::from_str(&data).unwrap();
        from_disk_db(ddb);
        init_static_data();
    }
}
pub fn in_memory(m_url: Option<&str>) {
    println!("[db] creating an in-memory database");
    let db = DB::new();
    let mut guard = DB_I.lock().unwrap();
    let option_db = guard.deref_mut();
    *option_db=Some(db);
    drop(guard);
    init_static_data();
    if let Some(url) = m_url {
        generate_new_genesis(url.to_string());
    }
}

//Initializes static data, called by load_db
fn init_static_data() {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    let data = StaticInfo {
        key:db.pkey.clone(),
        addr:db.addr,
        in_memory:db.in_memory
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

pub fn db_in_memory() -> bool {
    let sd = S_DATA.get().unwrap();
    return sd.in_memory;
}

pub fn write_db() -> Result<(),Box<dyn Error>> {
    if db_in_memory() {
        return Ok(());
    }
    let ddb = to_disk_db();
    fs::write("server_db.json",&serde_json::to_string(&ddb)?)?;
    return Ok(());
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
pub fn find_by_domain(domain: &str) -> Vec<ChainEntry> {
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

///Returns the hash of the genesis block
pub fn get_genesis_hash() -> Option<String> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.get_genesis_hash();
}

/// Return the length of the local chain
pub fn get_chain_length() -> usize {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.chain.len();
}

/// Return the last common index between the local chain and a remote chain
pub fn last_common_index(remote: &Vec<ChainEntry>) -> Option<usize> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.last_common_index(remote);
}

/// Replace entries after position `after` with `new_entries`.
/// If `after` is not in the chain, do nothing.
pub fn replace(after: usize, new_entries: &[ChainEntry]) {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    db.replace(after, new_entries);
}

//all the info one might need to know about a peer/non-peer
pub struct NodeInfo {
    pub url: String,
    pub key: Rsa<Public>,
    pub addr: u64,
}

pub fn current_elector(cr: &CertRequest) -> NodeInfo {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    assert!(db.chain.len() != 0);
    return chain::elector_at(&db.chain, cr,db.chain.len()-1);
}

/// Add ChainEntries to the blockchain, returning false if the incoming ChainEntries are
/// incompatible with the existing chain.
pub fn fast_forward(v: Vec<ChainEntry>, verify: bool) -> bool {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.fast_forward(v, verify);
}
pub fn merge_compatible(chain: Vec<ChainEntry>) -> bool {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.merge_compatible(chain);
}

pub fn update_channel() -> Receiver<ChainEntry> {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");
    return db.update_channel();
}

///Generates a new genesis block with our info and url as the root of the blockchain.
///Self-signs our URL+key using a key who's info is thrown out when the function exits.
pub fn generate_new_genesis(url: String) {
    let mut guard = DB_I.lock().unwrap();
    let db = guard.deref_mut().as_mut().expect("should be initialized");

    //generate key to verify ourselves with
    let verifier_key = generate();

    let our_pubkey = private_to_public(&db.pkey);

    let sigin = x509_sign(verifier_key,our_pubkey,&url);


    let cr = CertRequest::new(&url);
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

