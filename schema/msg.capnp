@0x986b3393db1396c9;

struct Msg {
    enum Type {
        ping @0;
        pong @1;
    }
    contents :union {
        ping @0 :Ping;
        pong @1 :Pong;
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
    url @0: Text;
    verifierSig @1: Text;
    msgid @2: UInt64;
    msgSig @3: Text;
}

#todo: Add Update response, depends on knowing what a block looks like


#interface PointTracker {
#    addPoint @0 (p :Point) -> (totalPoints :UInt64);
#}
