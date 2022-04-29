"""Custom topology example

Two directly connected switches plus a host for each switch:

                     controller
                        |
                      switch L3
                /       |          \
              /         |           \
   switch L2         switch L2        switch L2
  /  |  |  \         /  |  |  \       /  |  |  \
 h1  h2 h3  h4      h1  h2 h3  h4    h1  h2 h3  h4   


Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""
from cgi import test
import time
from mininet.net import Mininet
from mininet.node import RemoteController  # CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo

class MyTopo( Topo ):
    "Exercise 2 topology"

    def build( self ):
        "Create custom topology"

        # Add hosts and switches

        switchL3 = self.addSwitch( 'L3', ip='10.0.0.1' )
        
        switchL2_A = self.addSwitch('L2A', ip='10.0.1.1' , defaultRoute='via 10.0.0.1')
        host1_A = self.addHost('h1A', ip='10.0.1.2' , defaultRoute=' via 10.0.1.1')
        host2_A= self.addHost('h2A', ip='10.0.1.3' , defaultRoute='via 10.0.1.1')
        host3_A = self.addHost('h3A', ip='10.0.1.4' , defaultRoute='via 10.0.1.1')
        host4_A = self.addHost('h4A', ip='10.0.1.5' , defaultRoute='via 10.0.1.1')
        
        switchL2_B = self.addSwitch('L2B' ,ip='10.0.2.1' , defaultRoute='via 10.0.0.1')
        host1_B = self.addHost('h1B', ip='10.0.2.2' , defaultRoute='via 10.0.2.1')
        host2_B= self.addHost('h2B', ip='10.0.2.3', defaultRoute='via 10.0.2.1')
        host3_B = self.addHost('h3B', ip='10.0.2.4', defaultRoute='via 10.0.2.1')
        host4_B = self.addHost('h4B', ip='10.0.2.5', defaultRoute='via 10.0.2.1')
        
        switchL2_C = self.addSwitch('L2C', ip='10.0.3.1' , defaultRoute='via 10.0.0.1')
        host1_C = self.addHost('h1C', ip='10.0.3.2', defaultRoute='via 10.0.3.1')
        host2_C= self.addHost('h2C', ip='10.0.3.3', defaultRoute='via 10.0.3.1')
        host3_C = self.addHost('h3C', ip='10.0.3.4', defaultRoute='via 10.0.3.1')
        host4_C = self.addHost('h4C', ip='10.0.3.5', defaultRoute='via 10.0.3.1')


        # Add links
        self.addLink( switchL3, switchL2_A, params2={'ip': '10.0.1.1/24'})
        self.addLink( switchL3, switchL2_B,   params2={'ip': '10.0.2.1/24'})
        self.addLink( switchL3, switchL2_C,params2={'ip': '10.0.3.1/24'})
        
        self.addLink( switchL2_A, host1_A)
        self.addLink( switchL2_A, host2_A)
        self.addLink( switchL2_A, host3_A)
        self.addLink( switchL2_A, host4_A)
        
        self.addLink( switchL2_B, host1_B)
        self.addLink( switchL2_B, host2_B)
        self.addLink( switchL2_B, host3_B)
        self.addLink( switchL2_B, host4_B)
        
        self.addLink( switchL2_C, host1_C)
        self.addLink( switchL2_C, host2_C)
        self.addLink( switchL2_C, host3_C)
        self.addLink( switchL2_C, host4_C)

topos = { 'mytopo': ( lambda: MyTopo() ) }


def test_RemoteController():
  topo = MyTopo()
  print("***TOPO created")
  net = Mininet(topo=topo, controller=None)
  net.addController('c0', controller=RemoteController, ip='127.0.0.1')
  print("***Controller added")
  
  
  net.staticArp()
  # Add routing for reaching networks that aren't directly connected
 # info(net['r1'].cmd("ip route add 10.1.0.0/24 via 10.100.0.2 dev r1-eth2"))
 # info(net['r2'].cmd("ip route add 10.0.0.0/24 via 10.100.0.1 dev r2-eth2"))
  
  net.start()
  time.sleep(1)
  print("*** Running CLI")
  CLI(net)
  print("***Stoping network")
  net.stop()


test_RemoteController()
