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
from mininet.net import Mininet, VERSION
from mininet.node import RemoteController  # CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from asyncio import protocols
from mininet.node import OVSSwitch

def topo():
  "Create custom topology"
  # Add hosts and switches
  net = Mininet(controller=RemoteController, switch=OVSSwitch)
  switchL3 = net.addSwitch( 'L3', protocols='OpenFlow13', dpid='0000000000000001')
  
  switchL2_A = net.addSwitch('L2A', protocols='OpenFlow13', dpid='0000000000000002')
  host1_A = net.addHost('h1A', ip='10.0.1.1/24' ,mac='00:00:00:00:00:01', defaultRoute=' via 10.0.1.254')
  host2_A= net.addHost('h2A', ip='10.0.1.2/24' ,mac='00:00:00:00:00:02', defaultRoute='via 10.0.1.254')
  host3_A = net.addHost('h3A', ip='10.0.1.3/24' ,mac='00:00:00:00:00:03', defaultRoute='via 10.0.1.254')
  host4_A = net.addHost('h4A', ip='10.0.1.4/24' ,mac='00:00:00:00:00:04', defaultRoute='via 10.0.1.254')
  
  switchL2_B = net.addSwitch('L2B', protocols='OpenFlow13', dpid='0000000000000003')
  host1_B = net.addHost('h1B', ip='10.0.2.1/24',mac='00:00:00:00:00:05' , defaultRoute='via 10.0.2.254')
  host2_B= net.addHost('h2B', ip='10.0.2.2/24',mac='00:00:00:00:00:06', defaultRoute='via 10.0.2.254')
  host3_B = net.addHost('h3B', ip='10.0.2.3/24',mac='00:00:00:00:00:07', defaultRoute='via 10.0.2.254')
  host4_B = net.addHost('h4B', ip='10.0.2.4/24',mac='00:00:00:00:00:08', defaultRoute='via 10.0.2.254')
  
  switchL2_C = net.addSwitch('L2C', protocols='OpenFlow13', dpid='0000000000000004')
  host1_C = net.addHost('h1C', ip='10.0.3.1/24',mac='00:00:00:00:00:09', defaultRoute='via 10.0.3.254')
  host2_C= net.addHost('h2C', ip='10.0.3.2/24',mac='00:00:00:00:00:10', defaultRoute='via 10.0.3.254')
  host3_C = net.addHost('h3C', ip='10.0.3.3/24',mac='00:00:00:00:00:11', defaultRoute='via 10.0.3.254')
  host4_C = net.addHost('h4C', ip='10.0.3.4/24',mac='00:00:00:00:00:12', defaultRoute='via 10.0.3.254')
  # Add links
  net.addLink( switchL3, switchL2_A)
  net.addLink( switchL3, switchL2_B)
  net.addLink( switchL3, switchL2_C, cls=TCLink, delay='5ms')
  
  net.addLink( switchL2_A, host1_A)
  net.addLink( switchL2_A, host2_A)
  net.addLink( switchL2_A, host3_A)
  net.addLink( switchL2_A, host4_A)
                                            
  net.addLink( switchL2_B, host1_B)
  net.addLink( switchL2_B, host2_B)
  net.addLink( switchL2_B, host3_B)
  net.addLink( switchL2_B, host4_B)
                                             
  net.addLink( switchL2_C, host1_C)
  net.addLink( switchL2_C, host2_C)
  net.addLink( switchL2_C, host3_C)
  net.addLink( switchL2_C, host4_C)
  
 
  c0=net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633, protocols='OpenFlow13')
  c1=net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow13')
  print("***Controller added")
  net.build()
  switchL2_A.start([c0])
  switchL2_B.start([c0])
  switchL2_C.start([c0])
  switchL3.start([c1])
  time.sleep(1)
  print("*** Running CLI")
  CLI(net)
  print("***Stoping network")
  net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    topo()