use std::error::Error;
use serde::{Deserialize,Serialize};
use serde_json::to_string as to_json;
use sha2::{Sha256, Digest};
use crate::msg_capnp::{chain_entry, cert_request};
use capnp::message::Builder;
use capnp::text::Reader as TextReader;


//TODO: Format uniformly across codebase, no 2 spaces+4 spaces+etc

pub fn calculate_data_hash(data: &String) -> String {
  let mut hasher = Sha256::new();
  hasher.update(data.as_bytes());
  let hash = hasher.finalize();
  return format!("{:x}",hash);
}


//TODO: Delete serde code here
//make requester pubkey not a string
#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct CertRequest {
    pub hash: String,
    pub url: String,
    pub requester_pubkey: String,
    pub created_time: i64,
}

impl CertRequest {  
  fn to_data_string(&self) -> String {
    let mut concat = self.url.clone();
    concat.push('|');
    concat.push_str(&self.requester_pubkey);
    return concat;
  }
  
  pub fn new(url: String, requester_pubkey: String, created_time: i64) -> CertRequest {
    let mut request = CertRequest {
      hash: "".to_string(),
      url,
      requester_pubkey,
      created_time,
    };
    request.update_hash();
    return request;
  }

  fn update_hash(&mut self) {
    let data_string = self.to_data_string();
    self.hash = calculate_data_hash(&data_string);
  }

  //delete method
  pub fn to_db_serialize(&self) -> String {
    return to_json(&self).unwrap();
  }

  pub fn to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
    let mut mb = Builder::new_default();
    let mut cr = mb.init_root::<cert_request::Builder>();

    cr.set_hash(TextReader::from(self.hash.as_str()));
    cr.set_url(TextReader::from(self.url.as_str()));
    cr.set_req_pubkey(TextReader::from(self.requester_pubkey.as_str()));
    cr.set_req_time(self.created_time);

    return mb;
  }

  pub fn from_reader(cr: cert_request::Reader) -> Result<Self,Box<dyn Error>> {
    let hash = cr.get_hash()?.to_string()?;
    let url = cr.get_url()?.to_string()?;
    let req_pubkey = cr.get_req_pubkey()?.to_string()?;
    let req_time = cr.get_req_time();

    return Ok(CertRequest {
      hash,
      url,
      requester_pubkey: req_pubkey,
      created_time: req_time,
    });
  }


  //rustify api
  pub fn is_valid_request(&self) -> bool {
    let hash = calculate_data_hash(&self.to_data_string());
    return hash == self.hash;
  }
}


//remove serde code, etc
#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct ChainEntry {
  pub hash: String,
  pub prev_hash: String,
  pub height: u64,
  pub signed_time: i64,
  pub verifier_signature: String, // may need more info on verifier
  pub msg_signature: String,      // May need to be abstracted out
  pub request: CertRequest,
}

impl ChainEntry {
  fn to_data_string(&self) -> String {
    let mut concat = self.prev_hash.clone();
    concat.push('|');
    concat.push_str(&self.height.to_string());
    concat.push('|');
    concat.push_str(&self.signed_time.to_string());
    concat.push('|');
    concat.push_str(&self.verifier_signature);
    concat.push('|');
    concat.push_str(&self.request.hash);
    return concat;
  }
  
  pub fn new(
    prev_hash: String,
    height: u64, 
    signed_time: i64,
    verifier_signature: String,
    msg_signature: String,
    request: CertRequest,
  ) -> ChainEntry {
    let mut entry = ChainEntry {
      hash: "".to_string(),
      prev_hash,
      height,
      signed_time,
      verifier_signature,
      msg_signature,
      request,
    };
    entry.update_hash();
    return entry;
  }

  pub fn update_hash(&mut self) {
    let data_string = self.to_data_string();
    self.hash = calculate_data_hash(&data_string);
  }

  pub fn to_db_serialize(&self) -> String {
    return serde_json::to_string(&self).unwrap();
  }

  pub fn to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
    let mut mb = Builder::new_default();
    let mut ce = mb.init_root::<chain_entry::Builder>();

    ce.set_hash(TextReader::from(self.hash.as_str()));
    ce.set_prev_hash(TextReader::from(self.prev_hash.as_str()));
    ce.set_height(self.height);
    ce.set_signed_time(self.signed_time);
    ce.set_verifier_sig(TextReader::from(self.verifier_signature.as_str()));
    ce.set_req_hash(TextReader::from(self.request.hash.as_str()));
    ce.set_url(TextReader::from(self.request.url.as_str()));
    ce.set_req_pubkey(TextReader::from(self.request.requester_pubkey.as_str()));
    ce.set_req_time(self.request.created_time);
    ce.set_msg_sig(TextReader::from(self.msg_signature.as_str()));

    return mb;
  }

  pub fn from_reader(ce: chain_entry::Reader) -> Result<Self,Box<dyn Error>> {
    let hash = ce.get_hash()?.to_string()?;
    let prev_hash = ce.get_prev_hash()?.to_string()?;
    let height = ce.get_height();
    let signed_time = ce.get_signed_time();
    let verifier_signature = ce.get_verifier_sig()?.to_string()?;
    let msg_signature = ce.get_msg_sig()?.to_string()?;
    let req_hash = ce.get_req_hash()?.to_string()?;
    let url = ce.get_url()?.to_string()?;
    let req_pubkey = ce.get_req_pubkey()?.to_string()?;
    let req_time = ce.get_req_time();

    let request = CertRequest {
      hash: req_hash,
      url,
      requester_pubkey: req_pubkey,
      created_time: req_time,
    };
    return Ok(ChainEntry {
      hash,
      prev_hash,
      height,
      signed_time,
      verifier_signature,
      msg_signature,
      request,
    });
  }

  pub fn is_genesis(&self) -> bool {
    // TODO: update this function to compare with the real genesis block
    return self.prev_hash == "".to_string();
  }

}

pub fn verify_entry(entry: &ChainEntry, prev_entry: &ChainEntry) -> bool {
  // TODO: add consensus checks and independent verification
  if entry.prev_hash != prev_entry.hash {
    return false;
  }
  let hash = calculate_data_hash(&entry.to_data_string());
  return hash == entry.hash;
}

pub fn is_valid_chain(chain: &Vec<ChainEntry>, genesis_root: bool) -> bool {
  assert!(chain.len() > 0);

  if genesis_root && !chain[0].is_genesis() {
    return false;
  }
  let mut prev_entry = &chain[0];
  for entry in chain.iter().skip(1) {
    if !verify_entry(entry, prev_entry) {
      return false;
    }
    prev_entry = entry;
  }
  return true;
}
