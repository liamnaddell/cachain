from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )
        h7 = self.addHost( 'h7' )
        h8 = self.addHost( 'h8' )
        h9 = self.addHost( 'h9' )
        h10 = self.addHost( 'h10' )

        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )

        # Hosts 1-5 connected
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )
        self.addLink( h4, s1 )
        self.addLink( h5, s1 )

        # Hosts 6-10 connected
        self.addLink( h6, s2 )
        self.addLink( h7, s2 )
        self.addLink( h8, s2 )
        self.addLink( h9, s2 )
        self.addLink( h10, s2 )

        # These guys need to forward things ;)
        self.addLink( h3, s2 )
        self.addLink( h7, s1 )
        self.addLink( h5, s2 )
        self.addLink( h10, s1 )


topos = { 'mytopo': ( lambda: MyTopo() ) }

