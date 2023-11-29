use std::error::Error;
use serde::{Deserialize,Serialize};
use sha2::{Sha256, Digest};
use crate::msg_capnp::{chain_entry, cert_request};
use capnp::message::Builder;
use capnp::text::Reader as TextReader;
use crate::*;



///Calculates sha256 data hash
pub fn calculate_data_hash(data:&Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_slice());
    let hash = hasher.finalize();
    return format!("{:x}",hash);
}


#[derive(Serialize,Deserialize,Clone,Debug)]
pub struct CertRequest {
    pub src: u64,
    pub hash: String,
    pub url: String,
    pub requester_pubkey: String,
    pub created_time: u64,
}
impl CertRequest {  
   ///Serializes the certRequest data to a string
  fn to_data_string(&self) -> String {
    let mut concat = self.url.clone();
    concat.push('|');
    concat.push_str(&format!("{}|{}",self.src,self.created_time));
    concat.push_str(&self.requester_pubkey);
    return concat;
  }
  
  ///Creates a new CertRequest for a URL (that we own)
  pub fn new(url: &str) -> CertRequest {
    let mut request = CertRequest {
      src: db::get_addr(),
      hash: "".to_string(),
      url:url.to_string(),
      requester_pubkey:String::from_utf8(serialize_pubkey(&db::get_key())).unwrap(),
      created_time:time_now(),
    };
    request.update_hash();
    return request;
  }

  fn update_hash(&mut self) {
    let data_string = Vec::from(self.to_data_string().as_bytes());
    self.hash = calculate_data_hash(&data_string);
  }

  //Serializes to a capnp builder
  pub fn to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
    let mut mb = Builder::new_default();
    let mut cr = mb.init_root::<cert_request::Builder>();
    cr.set_hash(TextReader::from(self.hash.as_str()));
    cr.set_url(TextReader::from(self.url.as_str()));
    cr.set_req_pubkey(TextReader::from(self.requester_pubkey.as_str()));
    cr.set_req_time(self.created_time);

    return mb;
  }

  ///Serializes to an advert capnp builder
  pub fn to_advert_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
    let mut mb = Builder::new_default();
    let msg = mb.init_root::<msg::Builder>();
    let cts = msg.init_contents();
    let mut adv = cts.init_advert();
    adv.set_src(db::get_addr());
    let adv_kind = adv.reborrow().init_kind();
    let mut cr = adv_kind.init_cr();
    cr.set_src(self.src);
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
    let src = cr.get_src();

    return Ok(CertRequest {
        src,
      hash,
      url,
      requester_pubkey: req_pubkey,
      created_time: req_time,
    });
  }

  pub fn is_valid_request(&self) -> bool {
      let dsbytes = Vec::from(self.to_data_string().as_bytes());
    let hash = calculate_data_hash(&dsbytes);
    return hash == self.hash;
  }
}

///A challenge request sent by the verifier to the person who wants to be verified
#[derive(Debug)]
pub struct Challenge {
    pub src: u64,
    pub dest: u64,
    //the challenge string
    pub chal_str: String,
    //the time the challenge was issued (calculated by the verifier)
    pub time: u64,
}

impl Challenge {
    ///Create a new challenge with str chal_str, with destination being the node who wants to be
    ///verified
    pub fn new(dest: u64, chal_str: String) -> Self {
        return Challenge {
            src: db::get_addr(),
            dest,
            chal_str,
            time:time_now(),
        };
    }
    ///Convert challenge string to capnp message
    pub fn to_msg(&self) -> Vec<u8> {
        let mut message = Builder::new_default();
        let msg_builder = message.init_root::<msg_capnp::msg::Builder>();
        let c_b = msg_builder.init_contents();
        let mut b = c_b.init_challenge();
        b.set_src(self.src);
        b.set_dest(self.dest);
        b.set_challenge_string(text::Reader::from(self.chal_str.as_str()));

        let v = serialize::write_message_to_words(&message);

        return v;
    }
    pub fn from_reader(r: challenge::Reader) -> Result<Self,Box<dyn Error>>  {
        let src = r.get_src();
        let dest = r.get_dest();
        let time = r.get_time();
        let chal_str = r.get_challenge_string()?.to_string()?;
        return Ok(Challenge{src,dest,chal_str,time});

    }
}

#[derive(Serialize,Deserialize,Clone)]
///A serializable (to both disk and network) ChainEntry
pub struct ChainEntry {
  pub hash: String,
  pub prev_hash: String,
  pub height: u64,
  pub signed_time: u64,
  pub verifier_signature: Vec<u8>,
  pub msg_signature: Vec<u8>,
  pub request: CertRequest,
}
use std::fmt;
impl fmt::Display for ChainEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainEntry {{ hash: {}, prev_hash: {}, signed_time: {}, verifier_signature: {}, msg_signature: {}, request: {:?} }}" , self.hash,self.prev_hash,self.signed_time,self.verifier_signature.len(),self.msg_signature.len(),self.request)
    }
}
impl ChainEntry {
  fn to_data_string(&self) -> Vec<u8> {
    let mut concat = vec!();
    concat.extend_from_slice(self.prev_hash.as_bytes());
    concat.push(b'|');
    //concat.extend_from_slice(&self.height());
    concat.push(b'|');
    concat.extend_from_slice(&self.signed_time.to_string().as_bytes());
    concat.push(b'|');
    concat.extend_from_slice(&self.verifier_signature);
    concat.push(b'|');
    concat.extend_from_slice(self.request.hash.as_bytes());
    return concat;
  }
  
  pub fn new(
    prev_hash: String,
    height: u64, 
    signed_time: u64,
    verifier_signature: Vec<u8>,
    priv_key: Rsa<Private>, /* used to calculate message signature */
    request: CertRequest,
  ) -> ChainEntry {
    let mut entry = ChainEntry {
      hash: "".to_string(),
      prev_hash,
      height,
      signed_time,
      verifier_signature,
      msg_signature:vec!(),
      request,
    };
    //need to update hash before we can sign the request
    entry.update_hash();
    let data = entry.to_data_string();
    entry.msg_signature=sign(priv_key,data);
    return entry;
  }

  pub fn update_hash(&mut self) {
    let data_string = self.to_data_string();
    self.hash = calculate_data_hash(&data_string);
  }

  ///Converts to capnp message builder
  pub fn to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
    let mut mb = Builder::new_default();
    let mut ce = mb.init_root::<chain_entry::Builder>();

    ce.set_hash(TextReader::from(self.hash.as_str()));
    ce.set_prev_hash(TextReader::from(self.prev_hash.as_str()));
    ce.set_height(self.height);
    ce.set_signed_time(self.signed_time);
    ce.set_verifier_sig(self.verifier_signature.as_slice());
    ce.set_req_hash(TextReader::from(self.request.hash.as_str()));
    ce.set_url(TextReader::from(self.request.url.as_str()));
    ce.set_req_pubkey(TextReader::from(self.request.requester_pubkey.as_str()));
    ce.set_req_time(self.request.created_time);
    ce.set_msg_sig(self.msg_signature.as_slice());

    return mb;
  }

  pub fn from_reader(ce: chain_entry::Reader) -> Result<Self,Box<dyn Error>> {
    let hash = ce.get_hash()?.to_string()?;
    let prev_hash = ce.get_prev_hash()?.to_string()?;
    let height = ce.get_height();
    let signed_time = ce.get_signed_time();
    let verifier_signature = Vec::from(ce.get_verifier_sig()?);
    let msg_signature = Vec::from(ce.get_msg_sig()?);
    let req_hash = ce.get_req_hash()?.to_string()?;
    let url = ce.get_url()?.to_string()?;
    let req_pubkey = ce.get_req_pubkey()?.to_string()?;
    let req_time = ce.get_req_time();
    let src = ce.get_addr();

    let request = CertRequest {
        src:src,
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

  ///Checks if a ChainEntry is the genesis block
  pub fn is_genesis(&self) -> bool {
    // TODO: update this function to compare with the real genesis block
    return self.prev_hash == "".to_string();
  }

}

///Verifies that a blockchain entry is valid according to a couple algorithms that are not
///implemented yet. 
///See the functional requirements for the list of checks that need to be implemented
pub fn verify_entry(entry: &ChainEntry, prev_entry: &ChainEntry) -> bool {
  // TODO: add consensus checks and independent verification
  if entry.prev_hash != prev_entry.hash {
    return false;
  }
  let hash = calculate_data_hash(&entry.to_data_string());
  return hash == entry.hash;
}

///Runs the verifier on the entire chain
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
