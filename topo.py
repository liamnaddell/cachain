from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        liamHost = self.addHost( 'h3' )
        switch = self.addSwitch( 's1' )

        # Add links
        self.addLink( leftHost, switch )
        self.addLink( rightHost, switch )
        self.addLink( liamHost, switch )


topos = { 'mytopo': ( lambda: MyTopo() ) }

