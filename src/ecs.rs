use crate::*;
use crate::chain::{CertRequest, ChainEntry};
use std::sync::{RwLock,RwLockReadGuard};

pub fn init_ecs() -> Result<(), Box<dyn Error>> {
    let pkey = generate();
    let wskey = String::from_utf8(serialize_pubkey(&generate()))?;
    let vsig = "not a real signature lol".to_string();
    let r0 = CertRequest::new(
        "a.com".to_string(),
        wskey.clone(),
        0,
    );
    let c0 = ChainEntry::new(
        "".to_string(),
        0,
        0,
        wskey,
        vsig,
        r0,
    );
    let db = DB { chain: vec!(c0), pkey: pkey };
    //ew
    unsafe {
        let rwhandle = Box::new(RwLock::new(ECS {db}));
        ecs=Some(rwhandle);
    }
    return Ok(());
}
pub fn ecs_read() -> Result<RwLockReadGuard<'static, ECS>, Box<dyn Error>> {
    unsafe {
        if let Some(r) = &ecs {
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
}

//TODO: de-unsafe this api, I still think it's possible to do
static mut ecs: Option<Box<RwLock<ECS>>> = None;
