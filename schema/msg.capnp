@0x986b3393db1396c9;

struct Msg {
    enum Type {
        ping @0;
        pong @1;
        update @2;
        updateResponse @3;
        advert @4;
    }
    contents :union {
        ping @0 :Ping;
        pong @1 :Pong;
        update @2 :Update;
        updateResponse @3 :UpdateResponse;
        advert @4 :Advert;
    }
}

#TODO: Sign these
struct Challenge {
    src @0 :UInt64;
    dest @1 :UInt64;
    challengeString @2 :Text;
    time @3 : UInt64;
}

struct Ping {
    src @0 :UInt64;
    dest @1 :UInt64;
    key @2 :Text;
}

struct Pong {
    src @0 :UInt64;
    dest @1 :UInt64;
    #the pubkey of the pinged node
    key @2 :Text;
    #A list of peers
    peers @3 :List(Text);

}

struct Advert {
    src @0 :UInt64;
    dest @1 :UInt64;
    kind :union {
        cr @2 :CertRequest;
        ce @3 :Text;
        ch @4 :Challenge;
    }
}

struct GetRequest {
    src @0 :UInt64;
    dest @1 :UInt64;
    reqHash @2 :Text;
}

struct RequestData {
    src @0 :UInt64;
    dest @1 :UInt64;
    reqData @2 :CertRequest;
}

struct Update {
    src @0 :UInt64;
    dest @1 :UInt64;
    #update starting at id 
    startHash @2 :Text;
}

#TODO: Remove this struct once we replaced the code.
struct UpdateResponse {
    src @0 :UInt64;
    dest @1 :UInt64;
    startHash @2 :Text;
    bchain @3 :List(ChainEntry);
}

struct ChainEntry {
    hash @0 :Text;
    prevHash @1 :Text;
    height @2 :UInt64;
    signedTime @3 :UInt64;
    verifierSig @4 :Data;
    reqHash @5 :Text;
    url @6 :Text;
    reqPubkey @7 :Text;
    reqTime @8 :UInt64;
    msgSig @9 :Data;
    addr @10 :UInt64;
}

struct CertRequest {
    hash @0 :Text;
    url @1 :Text;
    reqPubkey @2 :Text;
    reqTime @3 :UInt64;
    src @4 :UInt64;
}

#todo: Add Update response, depends on knowing what a block looks like


#interface PointTracker {
#    addPoint @0 (p :Point) -> (totalPoints :UInt64);
#}
