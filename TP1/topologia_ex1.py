"""Custom topology example

Two directly connected switches plus a host for each switch:

    controller
        |
        |
      switch
    /  |  |  \
   h1  h2 h3  h4   


Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""
from cgi import test
import time
from mininet.net import Mininet
from mininet.node import RemoteController  # CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.topo import Topo

class MyTopo( Topo ):
    "Exercise 1 topology"

    def build( self ):
        "Create custom topology"

        # Add hosts and switches

        switch = self.addSwitch( 's1' )
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')


        # Add links
        self.addLink( switch, host1)
        self.addLink( switch, host2)
        self.addLink( switch, host3)
        self.addLink( switch, host4)

topos = { 'mytopo': ( lambda: MyTopo() ) }


def test_RemoteController():
    print('teste')
    

    topo = MyTopo()
    net = Mininet(topo=topo, controller=None)

    net.addController('c0', controller=RemoteController, ip='127.0.0.1')
    net.start()
    time.sleep(1)
    CLI(net)

    net.stop()


test_RemoteController()
