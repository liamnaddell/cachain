use crate::*;
use crate::chain::{CertRequest, ChainEntry};
use std::sync::{RwLock,RwLockReadGuard};

pub fn init_ecs(peer: &str, peerno: usize) -> Result<(), Box<dyn Error>> {
    let pkey = generate();
    let wskey = String::from_utf8(serialize_pubkey(&generate()))?;
    let vsig = "not a real signature lol".to_string();
    let c1 = ChainEntry {
        url: "a.com".to_string(),
        website_pubkey: wskey,
        verifier_signature: vsig.clone(),
        msgid: 0,
        msg_signature: vsig,
    };
    let db = DB { chain: vec!(c1), pkey: pkey };
    let peers = peers::Peers::new(peer,peerno);
    //ew
    unsafe {
        let rwhandle = Box::new(RwLock::new(ECS {db,peers,addr:0xdeadbeef}));
        ECS=Some(rwhandle);
    }
    return Ok(());
}
pub fn ecs_read() -> Result<RwLockReadGuard<'static, ECS>, Box<dyn Error>> {
    unsafe {
        if let Some(r) = &ECS {
            let option = r;
            let handle = option.read()?;
            return Ok(handle);
        } else {
            panic!("ecs read w/o initialization");
        }
    }

}
//singleton design pattern, stores threadsafe references to the database, etc
pub struct ECS {
    pub db: DB,
    pub addr: u64,
    pub peers: peers::Peers,
}

//TODO: de-unsafe this api, I still think it's possible to do
static mut ECS: Option<Box<RwLock<ECS>>> = None;
