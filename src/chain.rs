use serde::{Deserialize,Serialize};
use serde_json::to_string as to_json;
use sha2::{Sha256, Digest};

pub fn calculate_data_hash(data: &String) -> String {
  let mut hasher = Sha256::new();
  hasher.update(data.as_bytes());
  let hash = hasher.finalize();
  return format!("{:x}",hash);
}

#[derive(Serialize, Deserialize,Clone)]
pub struct CertRequest {
  hash: String,
  url: String,
  requester_pubkey: String,
}

impl CertRequest {  
  fn to_data_string(&self) -> String {
    let mut concat = self.url.clone();
    concat.push('|');
    concat.push_str(&self.requester_pubkey);
    return concat;
  }
  
  pub fn new(url: String, requester_pubkey: String) -> CertRequest {
    let mut request = CertRequest {
      hash: "".to_string(),
      url,
      requester_pubkey,
    };
    request.update_hash();
    return request;
  }

  fn update_hash(&mut self) {
    let data_string = self.to_data_string();
    self.hash = calculate_data_hash(&data_string);
  }

  pub fn to_db_serialize(&self) -> String {
    return to_json(&self).unwrap();
  }
}

pub fn is_valid_request(req: &CertRequest) -> bool {
  let hash = calculate_data_hash(&req.to_data_string());
  return hash == req.hash;
}

#[derive(Serialize, Deserialize,Clone)]
pub struct ChainEntry {
  hash: String,
  prev_hash: String,
  timestamp: i64,
  verifier_signature: String, // may need more info on verifier
  request: CertRequest,
}

impl ChainEntry {
  fn to_data_string(&self) -> String {
    let mut concat = self.prev_hash.clone();
    concat.push('|');
    concat.push_str(&self.timestamp.to_string());
    concat.push('|');
    concat.push_str(&self.verifier_signature);
    concat.push('|');
    concat.push_str(&self.request.hash);
    return concat;
  }
  
  pub fn new(
    prev_hash: String, 
    timestamp: i64, 
    verifier_signature: String,
    request: CertRequest,
  ) -> ChainEntry {
    let mut entry = ChainEntry {
      hash: "".to_string(),
      prev_hash,
      timestamp,
      verifier_signature,
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
}

pub fn is_genesis(entry: &ChainEntry) -> bool {
  // TODO: update this function to compare with the real genesis block
  return entry.prev_hash == "".to_string();
}

pub fn is_valid_entry(entry: &ChainEntry, prev_entry: &ChainEntry) -> bool {
  // TODO: add consensus checks
  if entry.prev_hash != prev_entry.hash {
    return false;
  }
  let hash = calculate_data_hash(&entry.to_data_string());
  return hash == entry.hash;
}

pub fn is_valid_chain(chain: &Vec<ChainEntry>, genesis_root: bool) -> bool {
  assert!(chain.len() > 0);

  if genesis_root && !is_genesis(&chain[0]) {
    return false;
  }
  let mut prev_entry = &chain[0];
  for entry in chain.iter().skip(1) {
    if !is_valid_entry(entry, prev_entry) {
      return false;
    }
    prev_entry = entry;
  }
  return true;
}