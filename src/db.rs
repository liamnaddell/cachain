use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Private};
use std::fs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::ops::{Deref,DerefMut};
use std::cmp::min;
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

}

use rand::random;
impl DB {
    ///Generates a new db with a new pkey and a random address
    pub fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey, addr:random(), tx: None};
    }
    fn add_block(&mut self, ce: ChainEntry) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(ce.clone());
        }
        self.chain.push(ce);
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
                self.add_block(new_head.clone());
            } else {
                return false;
            }
        }
        return true;
    }
    pub fn get_elector_seed(&self, cr: &CertRequest) -> u64 {
        let tiph = self.get_tip_hash().expect("Shouldn't be called on 0-size blockchain");
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
            self.fast_forward(chain);
            return true;
        }
        let max = min(chain.len(),self.chain.len());
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
    //returns a channel that updates to the chain are sent on
    pub fn update_channel(&mut self) -> Receiver<ChainEntry> {
        let (tx,rx) = channel();
        self.tx=Some(tx);
        return rx;
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
    let db = DB { chain: ddb.chain, pkey: rsa,addr:ddb.addr, tx: None};
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
        println!("[db] creating a new db");
        let db = DB::new();
        let mut guard = DB_I.lock().unwrap();
        let option_db = guard.deref_mut();
        *option_db=Some(db);
        drop(guard);
        let ddb = to_disk_db();
        fs::write(file,&serde_json::to_string(&ddb).unwrap()).unwrap();
    } else {
        println!("[db] reading db from {}",file);
        let data = fs::read_to_string(file).unwrap();
        let ddb: DiskDB = serde_json::from_str(&data).unwrap();
        from_disk_db(ddb);
    }
    init_static_data();
}
pub fn in_memory() {
    println!("[db] creating an in-memory database");
    let db = DB::new();
    let mut guard = DB_I.lock().unwrap();
    let option_db = guard.deref_mut();
    *option_db=Some(db);
    drop(guard);
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
/// We can consider the chain to be a probability space, and by choosing a random* (see note below)
/// number, we can pick an entry from the chain, who will become the verifer.
/// We also want to bias the number towards senority, so we will pick a linear distribution, with 
/// $\sum^\infty_0 p(x)dx=1$ as is expected for any discrete/continuous distribution, where p(x) is
/// the probability any individual chainentry is picked
/// The way we bias towards senority is as follows:
/// Consider a chain with n entries, we chose that the root of che chain will be R times as likely to
/// become the verifier than it would under a uniform distribution.
/// We then choose that the tip of the chain has a 0% probability of becoming the verifier.
/// We then linearly interpolate the relative probability that each node becomes the verifier.
/// To make this discrete, let node 1 get 5 tickets, node 2 get 4, node 3 gets 3, node 2 gets 2,
/// and node 1 gets 1. then, we take our random number, modulo it by 5+4+3+2+1=15, to get our
/// answer.
/// ----------------------------------
///           5 \
/// # of tick 3  -------\
///  ets      1          --------\
///             N1      N2       N3 
///                 node number
///----------------------------------
///
/// We then sum the tickets, then use the random number modulo sum as our answer (this excludes the
/// tip of the chain!)
///
///
/// * about those random numbers.
/// Everybody needs to agree on who the verifier is, that way elections work properly.
/// However, we also must acommodate that some verifiers won't do their job, so different cert
/// requests should get different verifiers. As such, some unique property of the current state of
/// the chain, + the current CertRequest should uniquely determine the verifier. 
/// We will use the time the CertRequest was created, plus, the bytes of the current tip of the
/// chain, to determine who the verifier is. 
/// A note on the weakness of the protocol:
/// by allowing the requester to influence who verifies them, we open ourselves up to collusion
/// between nodes, which is the worst case protocol scenario. Ideally, we would be able to avoid
/// this, however, this protocol is a proof-of-concept, not the final iteration.
/// This deficiency could be fixed either by changing the election function, or by introducing
/// multiple verifiers. Introducing multiple verifiers would make it nearly-impossible to collude,
/// even if you are able to bias selection by choosing a specific time to issue the CertRequest.
pub fn current_elector(cr: &CertRequest) -> NodeInfo {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    //shouldn't call current_elector on an empty chain (doy)
    assert!(db.chain.len() != 0);


    let randint: u64 = db.get_elector_seed(cr);
    let n = db.chain.len();

    //the number of tickets node 1 gets
    let first_guy_tickets=5.0;

    //node numbers go from 1 (root of chain) to n (tip)
    //this closure is the number of tickets a node gets
    let f = |x: usize| -> f64 {
        let x = x as f64;
        let n = n as f64;
        let factor = {
            if x != n {
                n/(n-x)
            } else {
                //this case shouldn't happen
                1.0
            }
        };
        first_guy_tickets/factor
    };

    //there's obviously a better way of doing this, I can't figure it out at the moment
    let total_tickets = ((1..(n-1)).map(f).sum::<f64>()).floor() as u64;
    //a reasonable upper bound...
    assert!(total_tickets < (5*n) as u64);

    //I'm aware this isn't an even distribution, this modulo biases towards senority

    //TODO: Find a better way if we have time, this algorithm should be O(1) instead its O(n),
    //where n is the length of the chain, which will only work for relatively short chains
    let winner_ce_number = {
        if total_tickets != 0 {
            let winner_ticket = randint % total_tickets;
            let mut sum = 0.0;
            let mut res = None;
            for i in 1..n {
                if (sum as u64) == winner_ticket {
                    res=Some(i);
                    break;
                }
                sum+=f(i);
            }
            res
        } else {
            //there's only 1 entry in the chain
            Some(0)
        }
    };
    //this computation should *literally* never fail
    let winner_ce_number = winner_ce_number.unwrap();

    //casting to a usize is safe here because the length of the chain will never be larger than a
    //32 bit integer, because there will never be 4 billion websites (i.e. more websites than ipv4 addresses)
    //plus there will likely be no more than 100 of these on our chain if we really go ham on testing.
    let entryno = winner_ce_number as usize;
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

    let sigin = x509_sign(verifier_key,our_pubkey);


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

