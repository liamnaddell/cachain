from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        cHost = self.addHost( 'h2' )
        rightHost = self.addHost( 'h3' )
        switch = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )

        # Add links
        self.addLink( leftHost, switch )
        self.addLink( switch, cHost )
        self.addLink( cHost, switch2 )
        self.addLink( switch2, rightHost )


topos = { 'mytopo': ( lambda: MyTopo() ) }

