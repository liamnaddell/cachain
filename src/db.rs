use openssl::rsa::Rsa;
use openssl::pkey::{PKey,Private};
use std::fs;
use crate::*;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::ops::{Deref,DerefMut};
use crate::chain::*;


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
    fn new() -> DB {
        let v = vec!();
        let pkey = generate();
        return DB { chain: v, pkey: pkey, addr:random()};
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
}

pub fn get_key() -> Rsa<Private> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.pkey.clone();
}

//TODO: THIS IS REALLY DUMB
pub fn get_chain() -> Vec<ChainEntry> {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.chain.clone();
}

//TODO: This is also stupid, put this data in read-only structure somewhere else with no mutex
pub fn get_addr() -> u64 {
    let guard = DB_I.lock().unwrap();
    let db = guard.deref().as_ref().expect("should be initialized");
    return db.addr;
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

