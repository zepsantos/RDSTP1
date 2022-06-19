from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import ether

from ryu.lib.mac import haddr_to_bin
from ryu.lib import mac
from ryu.app.wsgi import ControllerBase
from collections import defaultdict


from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
import copy



class Exercicio2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Exercicio2, self).__init__(*args, **kwargs)
        self.macToPort = {}
        self.L3SwitchMaps = defaultdict({})
        #self.ipToPort = {'10.0.1.254': 1 ,'10.0.2.245': 2,'10.0.3.254': 3}
        #self.portToIP= {1: '10.0.1.254', 2: '10.0.2.254', 3:'10.0.3.254'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 1, match, actions)
        self.send_port_desc_stats_request(datapath)  

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        
    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        src_mac = self.L3SwitchMACs.get(port,None)
        ip_src = self.portToIP.get(port,None)
        if src_mac is None or ip_src is None:
            return
        pkt = self.build_arp_packet(pkt_ethernet,pkt_arp,ip_src,src_mac)
                                   
        self._send_packet(datapath, port, pkt)
        self.logger.info("ARP-Reply sent")

    def build_arp_packet(self,pkt_ethernet,pkt_arp,src_ip,src_mac):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                                   dst=pkt_ethernet.src,
                                                   src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                         src_mac=src_mac,
                                         src_ip=src_ip,
                                         dst_mac=pkt_arp.src_mac,
                                         dst_ip=pkt_arp.src_ip))
        return pkt                                        

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        
        src_mac = self.L3SwitchMACs.get(port,None)
        ip_src = self.portToIP.get(port,None)
        if src_mac is None or ip_src is None:
            return           
        pkt = self.build_icmp_packet(pkt_ethernet,pkt_ipv4,pkt_icmp,ip_src,src_mac)
        self._send_packet(datapath, port, pkt)    
        

    def build_icmp_packet(self,pkt_ethernet,pkt_ipv4, pkt_icmp,ip_src,src_mac):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                                           dst=pkt_ethernet.src,
                                                           src=src_mac))

        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                                   src=ip_src,
                                                   proto=pkt_ipv4.proto))

        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                                   csum=0,
                                                   data=pkt_icmp.data))
        return pkt
            
   
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        

    """@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        for p in ev.msg.body:
            self.L3SwitchMACs.update({p.port_no : p.hw_addr})
            #self.logger.info('Dicionario de MACS: %s %s', p.port_no, p.hw_addr)
        #print(self.L3SwitchMACs) 
        self.logger.info('Dicionario de MACS: %s', self.L3SwitchMACs)"""

    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.logger.info("ARP-Request sent")
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return
        
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            self._handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        """
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        """
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        # The Function get_host(self, None) outputs the list of hosts.
        self.topo_raw_hosts = copy.copy(get_host(self, None))

        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """

        self.logger.info(" \t" + "Current Links:")
        for l in self.topo_raw_links:
            self.logger.info(" \t\t" + str(l.dp.id) + "\n")

        self.logger.info(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            self.logger.info(" \t\t" + str(s))
            
        self.logger.info(" \t" + "Current Hosts:")
        for i in self.topo_raw_hosts:
            self.logger.info(" \t\t" + str(i))    
    
  
        
    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")
        
  