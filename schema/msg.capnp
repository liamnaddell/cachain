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
    msgid @2 :UInt32;
}

struct Pong {
    src @0 :UInt64;
    dest @1 :UInt64;

}


#interface PointTracker {
#    addPoint @0 (p :Point) -> (totalPoints :UInt64);
#}
