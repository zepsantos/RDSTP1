from email.policy import default
from logging import DEBUG
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import ether
import ipaddress
from collections import defaultdict

class Exercicio2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Exercicio2, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = defaultdict(lambda:defaultdict(None)) # datapath.id X ( arp-ip-src X( arp-mac-src,port))
        self.arp_buffer  = defaultdict(lambda: defaultdict(None))
        self.portToIP = {1:'10.0.1.254',2:'10.0.2.254',3:'10.0.3.254'}
        self.topologyMacs = defaultdict(lambda:defaultdict(None))
        self.subnetToPort = {'10.0.1.0':1 , '10.0.2.0':2,'10.0.3.0':3}
        self.logger.setLevel(DEBUG)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
        
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
   

    
   
        
    def arpToGetLocation(self,datapath,pkt_eth, pkt_ipv4,pkt ):
        self.logger.info(f'arping to get Location {pkt_ipv4.dst}')
        subnet = self.stripSubnetFromIP(pkt_ipv4.dst)
        self.arp_buffer[datapath.id].setdefault(pkt_ipv4.dst, [])
        self.arp_buffer[datapath.id][pkt_ipv4.dst].append(pkt)

        port = self.subnetToPort.get(subnet,None)
        ip_src = self.portToIP.get(port,None)
        mac_src = self.topologyMacs[datapath.id][port]
        if port is not None and ip_src is not None:
            self.logger.info(f'locating arp {pkt_ipv4.dst} {ip_src} {port}')
            self.send_arp(datapath,1,mac_src,ip_src,"ff:ff:ff:ff:ff:ff",pkt_ipv4.dst, port)

    
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode == arp.ARP_REPLY:
            self.process_arp_reply(datapath,port,pkt_ethernet,pkt_arp)
            return
        if pkt_arp.opcode == arp.ARP_REQUEST:
            src_mac = self.topologyMacs[datapath.id][port]
            dstIp = pkt_arp.src_ip
            srcIp = pkt_arp.dst_ip
            dstMac = pkt_ethernet.src
            ip_src = self.portToIP.get(port,None)
            out_port = self.subnetToPort.get(self.stripSubnetFromIP(pkt_arp.dst_ip), None)
            self.logger.info(f'ip_src {ip_src} {pkt_arp.src_ip} {pkt_arp.src_mac}')
            if src_mac is None or ip_src is None:
                return
            self.arp_table[datapath.id][dstIp] = (dstMac,port)
            self.send_arp(datapath,2,src_mac,srcIp,dstMac,dstIp,out_port)
            
            
            # Se forem da mesma subnet responder ao request
            """if self.stripSubnetFromIP(ip_src) == self.stripSubnetFromIP(pkt_arp.dst_ip):
                self.logger.info(f'answering back to arp request')
                return
            else:
                self.send_arp(datapath,pkt_arp.opcode,src_mac,pkt_arp.src_ip,pkt_ethernet,pkt_arp,pkt_arp.dst_ip, )
                self.logger.info(f'not on the same network')"""

            

    def process_arp_reply(self,datapath,port,pkt_ethernet,pkt_arp):
        self.logger.info(f'process arp reply {pkt_arp.src_ip} {pkt_arp.dst_ip} {pkt_arp.dst_mac} {pkt_arp.src_mac} {port}')
        self.arp_table[datapath.id][pkt_arp.src_ip] = (pkt_arp.src_mac, port)
        #self.logger.info(f'arp-table_reply {self.arp_table}')
        
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, 
                                                    ipv4_dst=pkt_arp.src_ip)

        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_src=pkt_arp.dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_dst=pkt_arp.src_mac),
                datapath.ofproto_parser.OFPActionDecNwTtl(),
                datapath.ofproto_parser.OFPActionOutput(port)]

        self.add_flow(datapath, 2000, match, actions)
        for packet in self.arp_buffer[datapath.id][pkt_arp.src_ip]:
            self.send_packet_toDatapath(datapath, packet, port, pkt_arp.dst_mac, pkt_arp.src_mac)
        self.logger.info(f'arp-table_reply processed')
        
    
    def send_packet_toDatapath(self,datapath,packet,port,dst_mac,src_mac):

        actions = [ 
                datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
                datapath.ofproto_parser.OFPActionDecNwTtl(),
                datapath.ofproto_parser.OFPActionOutput(port)]

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=packet)
        datapath.send_msg(out)                          

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return True
        
        src_mac = pkt_ethernet.dst# MAC DA INTERFACE DO ROUTER LIGADA AO SWITCH
        ip_src = self.portToIP.get(port,None)
        if src_mac is None or ip_src is None:
            return False          
        if pkt_ipv4.dst == ip_src:
            self.logger.info(f'ip : {pkt_ipv4.src} is pinging {pkt_ipv4.dst} srcmac para teste {src_mac}')
            pkt = self.build_icmp_packet(pkt_ethernet,pkt_ipv4,pkt_icmp,ip_src,src_mac)
            self._send_packet(datapath, port, pkt) 
            return False
        return True
             
           
    def stripSubnetFromIP(self,ip):
        network = ipaddress.IPv4Network(ip+'/255.255.255.0', strict=False)
        return str(network.network_address)
    

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
        data = pkt.data
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        

   


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
        
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return
        
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            status = self._handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp)
            self.logger.info(f' icmp status {status}')
            if not status:
                return

        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6
            return
        dst = pkt_ethernet.dst
        src = pkt_ethernet.src
        ip_dst = pkt_ipv4.dst
        subnet = self.stripSubnetFromIP(ip_dst)
        self.logger.info(f'arptable: {self.arp_table[datapath.id]}')
        if subnet in self.subnetToPort:
            out_port = self.subnetToPort[subnet]
            #self.logger.info(f'working 1')
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, 
                                                    ipv4_dst=ip_dst)
            desc = self.arp_table[datapath.id].get(ip_dst,None)
            #self.logger.info(f'working 2')
            if desc is None:
                self.logger.info(f'no path to {ip_dst}')
                self.arpToGetLocation(datapath,pkt_ethernet,pkt_ipv4,pkt)
                return
            else:
                mcdst,tmpport = desc
                self.logger.info(f'arptableentry exists {mcdst} {tmpport} {ip_dst}')
               

            
            
            if out_port != ofproto.OFPP_FLOOD:
                actions = [ 
                    parser.OFPActionSetField(eth_src=dst),
                    parser.OFPActionSetField(eth_dst=mcdst),
                    parser.OFPActionDecNwTtl(),
                    parser.OFPActionOutput(tmpport)]
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                   self.add_flow(datapath, 1999, match, actions, msg.buffer_id)
                   return
                else:
                    self.add_flow(datapath, 1999, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            actions = [parser.OFPActionOutput(tmpport)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)

            datapath.send_msg(out)
        else:
            #ICMP UNREACHABLE
            pass
    
    
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for p in ev.msg.body:
            self.logger.info(f'dpid :  {dpid} {p.port_no} {p.hw_addr}')
            self.topologyMacs[dpid][p.port_no] = p.hw_addr
        self.logger.info('config done')