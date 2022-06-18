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
from mininet.node import Node


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def topo():
  "Create custom topology"
  # Add hosts and switches
  net = Mininet(controller=RemoteController, switch=OVSSwitch)
  
  switchL3 = net.addSwitch( 'L3', protocols='OpenFlow13')
  
  router_A = net.addHost( 'rA', cls=LinuxRouter, mac='00:00:00:00:01:00',ip='10.0.0.1/24')
  switchL2_A = net.addSwitch('L2A', protocols='OpenFlow13')
  host1_A = net.addHost('h1A', ip='10.0.1.1/24' ,mac='00:00:00:00:00:01', defaultRoute=' via 10.0.1.254')
  host2_A= net.addHost('h2A', ip='10.0.1.2/24' ,mac='00:00:00:00:00:02', defaultRoute='via 10.0.1.254')
  host3_A = net.addHost('h3A', ip='10.0.1.3/24' ,mac='00:00:00:00:00:03', defaultRoute='via 10.0.1.254')
  host4_A = net.addHost('h4A', ip='10.0.1.4/24' ,mac='00:00:00:00:00:04', defaultRoute='via 10.0.1.254')
  
  router_B = net.addHost( 'rB', cls=LinuxRouter, mac='00:00:00:00:02:00',ip='10.0.0.1/24' )
  switchL2_B = net.addSwitch('L2B', protocols='OpenFlow13')
  host1_B = net.addHost('h1B', ip='10.0.2.1/24',mac='00:00:00:00:00:05' , defaultRoute='via 10.0.2.254')
  host2_B= net.addHost('h2B', ip='10.0.2.2/24',mac='00:00:00:00:00:06', defaultRoute='via 10.0.2.254')
  host3_B = net.addHost('h3B', ip='10.0.2.3/24',mac='00:00:00:00:00:07', defaultRoute='via 10.0.2.254')
  host4_B = net.addHost('h4B', ip='10.0.2.4/24',mac='00:00:00:00:00:08', defaultRoute='via 10.0.2.254')
  
  router_C = net.addHost( 'rC', cls=LinuxRouter, mac='00:00:00:00:03:00' ,ip='10.0.0.1/24')
  switchL2_C = net.addSwitch('L2C', protocols='OpenFlow13')
  host1_C = net.addHost('h1C', ip='10.0.3.1/24',mac='00:00:00:00:00:09', defaultRoute='via 10.0.3.254')
  host2_C= net.addHost('h2C', ip='10.0.3.2/24',mac='00:00:00:00:00:10', defaultRoute='via 10.0.3.254')
  host3_C = net.addHost('h3C', ip='10.0.3.3/24',mac='00:00:00:00:00:11', defaultRoute='via 10.0.3.254')
  host4_C = net.addHost('h4C', ip='10.0.3.4/24',mac='00:00:00:00:00:12', defaultRoute='via 10.0.3.254')
  
  
  # Add links
  #net.addLink( router_A, router_B)
  #net.addLink( router_B, router_C)
  #net.addLink( router_C, router_A,  delay='5ms')
  
  
  net.addLink(router_A,
              router_B,
              intfName1='rA-eth2',
              intfName2='rB-eth2',
              params1={'ip': '10.100.0.1/24'},
              params2={'ip': '10.100.0.2/24'})
        
  net.addLink(router_B,
              router_C,
              intfName1='rB-eth3',
              intfName2='rC-eth2',
              params1={'ip': '10.100.0.2/24'},
              params2={'ip': '10.100.0.3/24'})

  net.addLink(router_C,
              router_A,
              intfName1='rC-eth3',
              intfName2='rA-eth3',
              params1={'ip': '10.100.0.3/24'},
              params2={'ip': '10.100.0.1/24'},
              delay='5ms')
  
  
   # Add router-switch links in the same subnet
  net.addLink(switchL2_A,
               router_A,
               intfName2='rA-eth1',
               params2={'ip': '10.0.0.1/24'})
  
  net.addLink(switchL2_B,
               router_B,
               intfName2='rB-eth1',
               params2={'ip': '10.1.0.1/24'})
  
  net.addLink(switchL2_C,
               router_C,
               intfName2='rC-eth1',
               params2={'ip': '10.2.0.1/24'})
  
  #net.addLink( router_A, switchL2_A)
  #net.addLink( router_B, switchL2_B)
  #net.addLink( router_C, switchL2_C)
  
  #net.addLink( switchL3, switchL2_A)
  #net.addLink( switchL3, switchL2_B)
  #net.addLink( switchL3, switchL2_C)
  
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
  
  info(net['rA'].cmd("ip route add 10.1.0.0/24 via 10.100.0.2 dev rA-eth2"))
  info(net['rB'].cmd("ip route add 10.0.0.0/24 via 10.100.0.1 dev rB-eth2"))
  
  info('*** Routing Table on Router:\n')
  info(net['rA'].cmd('route'))
  info(net['rB'].cmd('route'))
  info(net['rC'].cmd('route'))
  time.sleep(1)
  print("*** Running CLI")
  CLI(net)
  print("***Stoping network")
  net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    topo()