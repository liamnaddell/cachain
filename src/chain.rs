use serde::{Deserialize,Serialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize,Clone)]
pub struct CertRequest {
  hash: String,
  url: String,
  requester_pubkey: String,
}

#[derive(Serialize, Deserialize,Clone)]
pub struct BlockHeader {
  block_hash: String,
  prev_hash: String,
  timestamp: i64,
  verifier_signature: String, // may need more info on verifier
}

#[derive(Serialize, Deserialize,Clone)]
pub struct ChainEntry {
  header: BlockHeader,
  request: CertRequest,
}

impl CertRequest {
  fn inter_serialize(&self) -> serde_json::Value {
    serdee_json::json!({
      "url": self.url,
      "requester_pubkey": self.requester_pubkey,
    }).unwrap()
  }
  
  pub fn new(url: String, requester_pubkey: String) -> CertRequest {
    let request = CertRequest {
      hash: "".to_string(),
      url,
      requester_pubkey,
    };
    request.update_hash();
    return request;
  }

  pub fn update_hash(&mut self) {
    self.hash = calculate_data_hash(self.inter_serialize().to_string());
  }

  pub fn to_json(&self) -> String {
    let intermediate = self.inter_serialize();
    intermediate["hash"] = self.hash;
    return intermediate.to_string();
  }
}

impl BlockHeader {
  pub fn inter_serialize(&self) -> serde_json::Value {
    serde_json::json!({
      "prev_hash": self.prev_hash,
      "timestamp": self.timestamp,
      "verifier_signature": self.verifier_signature,
    }).unwrap()
  }

  pub fn new(
    prev_hash: String, 
    timestamp: i64, 
    verifier_signature: String
  ) -> BlockHeader {
    let header = BlockHeader {
      block_hash: "".to_string(),
      prev_hash,
      timestamp,
      verifier_signature,
    };
    header.update_hash();
    return header;
  }

  pub fn update_hash(&mut self) {
    self.block_hash = calculate_data_hash(self.inter_serialize().to_string());
  }

  pub fn to_json(&self) -> String {
    let intermediate = self.inter_serialize();
    intermediate["block_hash"] = self.block_hash;
    return intermediate.to_string();
  }
}

pub fn calculate_data_hash(data: String) -> String {
  let mut hasher = Sha256::new();
  hasher.update(data.as_bytes());
  let hash = hasher.finalize();
  return format!("{:x}",hash);
}

pub fn is_valid_request(req: &CertRequest) -> bool {
  let hash = calculate_json_hash(req.to_json());
  return hash == req.hash;
}

pub fn is_valid_block(block: &BlockHeader, prev_block: &BlockHeader) -> bool {
  if (block.prev_hash != prev_block.block_hash) {
    return fallse;
  }
  let hash = calculate_data_hash(block.to_json());
  return hash == block.block_hash;
}

pub fn is_valid_chain(chain: &Vec<ChainEntry>) -> bool {
  // TODO: before implementing this, need a genesis block
  false
}