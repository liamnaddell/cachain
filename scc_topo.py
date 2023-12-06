from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        switch = self.addSwitch( 's1' )

        # Add links
        self.addLink( h1, switch )
        self.addLink( h2, switch )
        self.addLink( h3, switch )


topos = { 'mytopo': ( lambda: MyTopo() ) }

