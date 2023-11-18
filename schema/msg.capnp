@0x986b3393db1396c9;

struct Msg {
    enum Type {
        ping @0;
        pong @1;
        update @2;
        updateResponse @3;
        advert @4;
        getRequest @5;
        requestData @6;
    }
    contents :union {
        ping @0 :Ping;
        pong @1 :Pong;
        update @2 :Update;
        updateResponse @3 :UpdateResponse;
        advert @4 :Advert;
        getRequest @5 :GetRequest;
        requestData @6 :RequestData;
    }
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
        cr @2 :Text;
        ce @3 :Text;
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
    startMsgid @2 :UInt32;
    #update ending at id, 0=all updates
    endMsgid @3 :UInt32;
}

#note: A more secure protocol would have the sender sign update responses
struct UpdateResponse {
    src @0 :UInt64;
    dest @1 :UInt64;
    bchain @2 :List(ChainEntry);
}

struct ChainEntry {
    hash @0 :Text;
    prevHash @1 :Text;
    height @2 :UInt64;
    signedTime @3 :Int64;
    verifierSig @4 :Text;
    reqHash @5 :Text;
    url @6 :Text;
    reqPubkey @7 :Text;
    reqTime @8 :Int64;
    msgSig @9 :Text;
}

struct CertRequest {
    hash @0 :Text;
    url @1 :Text;
    reqPubkey @2 :Text;
    reqTime @3 :Int64;
}

#todo: Add Update response, depends on knowing what a block looks like


#interface PointTracker {
#    addPoint @0 (p :Point) -> (totalPoints :UInt64);
#}
