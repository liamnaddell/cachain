use std::error::Error;
use serde::{Deserialize,Serialize};
use sha2::{Sha256, Digest};
use crate::msg_capnp::{chain_entry, cert_request};
use capnp::message::Builder;
use capnp::text::Reader as TextReader;
use crate::*;
use crate::db::NodeInfo;


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
        concat.push_str(&format!("{}|{}", self.src, self.created_time));
        concat.push_str(&self.requester_pubkey);
        return concat;
    }

    ///Creates a new CertRequest for a URL (that we own)
    pub fn new(url: &str) -> CertRequest {
        let mut request = CertRequest {
            src: db::get_addr(),
            hash: "".to_string(),
            url: url.to_string(),
            requester_pubkey: String::from_utf8(serialize_pubkey(&db::get_key())).unwrap(),
            created_time: time_now(),
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
    ///Convert challenge string to capnp advert message
    pub fn to_advert_msg(&self) -> Vec<u8> {
        let mut mb = Builder::new_default();
        let msg = mb.init_root::<msg::Builder>();
        let cts = msg.init_contents();
        let mut adv = cts.init_advert();
        adv.set_src(db::get_addr());
        adv.set_dest(self.dest);

        let adv_kind = adv.reborrow().init_kind();
        let mut b = adv_kind.init_ch();
        b.set_src(self.src);
        b.set_dest(self.dest);
        b.set_challenge_string(text::Reader::from(self.chal_str.as_str()));

        let v = serialize::write_message_to_words(&mb);

        return v;
    }
    pub fn to_chal_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut mb = Builder::new_default();
        let mut ch = mb.init_root::<challenge::Builder>();
        ch.set_src(self.src);
        ch.set_dest(self.dest);
        ch.set_challenge_string(TextReader::from(self.chal_str.as_str()));

        return mb;
    }
    /// Convert to a capnp builder
    pub fn to_builder(&self) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut mb = Builder::new_default();
        let msg = mb.init_root::<msg::Builder>();
        let cts = msg.init_contents();
        let mut adv = cts.init_advert();
        adv.set_src(db::get_addr());
        let adv_kind = adv.reborrow().init_kind();
        let mut ch = adv_kind.init_ch();
        ch.set_src(self.src);
        ch.set_dest(self.dest);
        ch.set_challenge_string(TextReader::from(self.chal_str.as_str()));

        return mb;
    }
    /// Return a hash of the challenge
    pub fn get_hash(&self) -> String {
        let mut concat = self.chal_str.clone();
        concat.push('|');
        concat.push_str(&self.src.to_string());
        concat.push('|');
        concat.push_str(&self.dest.to_string());
        concat.push('|');
        concat.push_str(&self.time.to_string());
        return calculate_data_hash(&Vec::from(concat.as_bytes()));
    }
    pub fn from_reader(r: challenge::Reader) -> Result<Self,Box<dyn Error>>  {
        let src = r.get_src();
        let dest = r.get_dest();
        let time = r.get_time();
        let chal_str = r.get_challenge_string()?.to_string()?;
        return Ok(Challenge{src,dest,chal_str,time});

    }
}

#[derive(Serialize, Deserialize, Clone)]
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
    pub fn to_data_string(&self) -> Vec<u8> {
        let mut concat = vec![];
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
            msg_signature: vec![],
            request,
        };
        //need to update hash before we can sign the request
        entry.update_hash();
        let data = entry.to_data_string();
        entry.msg_signature = sign(priv_key, data);
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

    pub fn from_reader(ce: chain_entry::Reader) -> Result<Self, Box<dyn Error>> {
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
            src: src,
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
        let g_hash = db::get_genesis_hash();
        match g_hash {
            Some(hash) => return hash == self.hash,
            None => {
                println!("No genesis hash found in db");
                return false;
            },
        }
    }
}

// Validate the entry of a chain. Does not verify correctness
pub fn validate_entry(entry: &ChainEntry, prev_entry: &ChainEntry) -> bool {
    if entry.prev_hash != prev_entry.hash {
        return false;
    }
    let hash = calculate_data_hash(&entry.to_data_string());
    return hash == entry.hash;
}

///Runs the validator on a chain
pub fn is_valid_chain(chain: &Vec<ChainEntry>, genesis_root: bool) -> bool {
    if chain.len() == 0 || genesis_root && !chain[0].is_genesis() {
        return false;
    }
    let mut prev_entry = &chain[0];
    for entry in chain.iter().skip(1) {
        if !validate_entry(entry, prev_entry) {
            return false;
        }
        prev_entry = entry;
    }
    return true;
}

pub fn get_elector_seed(chain: &Vec<ChainEntry>, cr: &CertRequest,pos:usize) -> u64 {
    let tiph = chain[pos].hash.clone();
    let randint = tiph.as_bytes().iter().fold(0,|acc,y| acc+(*y as u64)) 
        + cr.created_time;
    return randint;
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
pub fn elector_at(chain: &Vec<ChainEntry>, cr: &CertRequest, pos:usize) -> NodeInfo {
    //shouldn't call current_elector on an empty chain (doy)
    assert!(chain.len() != 0);
    let randint: u64 = get_elector_seed(chain, cr, pos);
    let n = pos+1;
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
    let total_tickets = ((0..(n-1)).map(f).sum::<f64>()).floor() as u64;
    //a reasonable upper bound...
    assert!(total_tickets < (5*n) as u64);
    //I'm aware this isn't an even distribution, this modulo biases towards senority
    //TODO: Find a better way if we have time, this algorithm should be O(1) instead its O(n),
    //where n is the length of the chain, which will only work for relatively short chains
    let mut res = None;
    if total_tickets != 0 {
        let winner_ticket = randint % total_tickets;
        let mut sum = 0.0;
        for i in 0..n-1 {
            sum+=f(i);
            let usum = sum as u64;
            if usum >= winner_ticket {
                res=Some(i);
                break;
            }
        }
    } else {
        //there's only 1 entry in the chain
        res=Some(0);
    }
    //this computation should *literally* never fail
    let winner_ce_number = res.unwrap();
    //casting to a usize is safe here because the length of the chain will never be larger than a
    //32 bit integer, because there will never be 4 billion websites (i.e. more websites than ipv4 addresses)
    //plus there will likely be no more than 100 of these on our chain if we really go ham on testing.
    let entryno = winner_ce_number as usize;
    let entry = &chain[entryno];
    let req = &entry.request;
    let ni = NodeInfo {url:req.url.clone(),key:deserialize_pubkey(&req.requester_pubkey),addr:req.src};
    return ni;
}

/// Validate and verify `entry` using an entry on the local chain at `prev_pos`
/// `entry` is supposed to be the next entry after the entry at `prev_pos`
pub fn verify_entry(chain: &Vec<ChainEntry>, entry: &ChainEntry, prev_pos: usize) -> bool {
    let prev = &chain[prev_pos];
    if !chain::validate_entry(entry, prev) {
        println!("[db] chain entry {} failed validation", entry.hash);
        return false;
    }
    // find the verifier of entry
    let ni = elector_at(chain, &entry.request, prev_pos);
    // check the signatures of entry using verifier details
    let rsa_pubkey = &ni.key;
    let data_string = entry.to_data_string();
    if !verify_signature(&rsa_pubkey, &data_string, &entry.msg_signature) {
        println!("[db] entry {} failed verification", entry.hash);
        return false;
    }
    return true;
}

/// Verify a given chain starting after a given position
pub fn verify_chain_after(chain: &Vec<ChainEntry>, after: usize) -> bool {
    if after >= chain.len() {
        println!("[chain_verifier] invalid position {} for chain of length {}", after, chain.len());
        return false;
    }
    // Verify the rest of the chain
    for i in after+1..chain.len() {
        if !verify_entry(chain, &chain[i], i-1) {
            return false;
        }
    }
    return true;
}