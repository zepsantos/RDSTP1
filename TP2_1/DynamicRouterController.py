import ipaddress
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib import addrconv
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from netaddr import *
import networkx as nx
from ryu.topology import event
# Below is the library used for topo discovery
from ryu.topology.api import get_switch, get_link
import copy

##TODO: VERIFICAR SE DATAPATH.id DA OS IDS 21,19,20

class DynamicRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicRouting, self).__init__(*args, **kwargs)
        # USed for learning switch functioning
        self.mac_to_port = {}
        # Holds the topology data and structure
        self.arp_table = defaultdict(lambda: defaultdict(None))  # datapath.id X ( arp-ip-src X( arp-mac-src,port))
        self.arp_buffer = defaultdict(lambda: defaultdict(None))
        self.dpidToIP = {19: '10.0.1.254', 20: '10.0.2.254', 21: '10.0.3.254'}
        self.subnetToDpid = {'10.0.1.0': 19, '10.0.2.0': 20, '10.0.3.0': 21}
        self.portHelper = {21: 1, 19: 1, 20: 1}
        self.idToDataPath = {}
        self.topologyMacs = defaultdict(lambda: defaultdict(None))
        self.topo_raw_switches = []
        self.topo_raw_links = []
        self.net = nx.DiGraph()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        self.idToDataPath[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('OFPSwitchFeatures received: '
                         '\n\tdatapath_id=0x%016x n_buffers=%d '
                         '\n\tn_tables=%d auxiliary_id=%d '
                         '\n\tcapabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
        self.install_initial_flows(datapath,ofproto,parser)


    def install_initial_flows(self,datapath,ofproto,parser):
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

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
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

    def arpToGetLocation(self, datapath, pkt_ipv4, pkt):
        self.arp_buffer[datapath.id].setdefault(pkt_ipv4.dst, [])
        self.arp_buffer[datapath.id][pkt_ipv4.dst].append(pkt)

        port = self.portHelper[datapath.id]
        ip_src = self.dpidToIP[datapath.id]
        mac_src = self.topologyMacs[datapath.id][port]
        if port is not None and ip_src is not None:
            self.send_arp(datapath, 1, mac_src, ip_src, "ff:ff:ff:ff:ff:ff", pkt_ipv4.dst, port)

        """ 
            somos o router
        
        """

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
            self.process_arp_reply(datapath, port, pkt_ethernet, pkt_arp)
            return
        if pkt_arp.opcode == arp.ARP_REQUEST:

            dpfromnetwork,out_port = self.getPortAndPid(pkt_arp.dst_ip)
            ip_src = self.dpidToIP[dpfromnetwork]
            if dpfromnetwork is None:
                return
            src_mac = self.topologyMacs[dpfromnetwork][out_port]
            dstIp = pkt_arp.src_ip
            srcIp = pkt_arp.dst_ip
            dstMac = pkt_ethernet.src

            if src_mac is None or ip_src is None:
                return
            self.arp_table[dpfromnetwork][dstIp] = (dstMac, out_port)
            datapath_to_send_arp = self.idToDataPath.get(dpfromnetwork,None)
            if datapath_to_send_arp is not None:
                self.send_arp(datapath_to_send_arp, 2, src_mac, srcIp, dstMac, dstIp, out_port)

            # Se forem da mesma subnet responder ao request
            """if self.stripSubnetFromIP(ip_src) == self.stripSubnetFromIP(pkt_arp.dst_ip):
                self.logger.info(f'answering back to arp request')
                return
            else:
                self.send_arp(datapath,pkt_arp.opcode,src_mac,pkt_arp.src_ip,pkt_ethernet,pkt_arp,pkt_arp.dst_ip, )
                self.logger.info(f'not on the same network')"""

    def getPortAndPid(self, ip):
        subnet = self.stripSubnetFromIP(ip)
        dpfromnetwork = self.subnetToDpid.get(subnet, None)
        out_port = self.portHelper.get(dpfromnetwork,None)
        return dpfromnetwork,out_port

    def process_arp_reply(self, datapath, port, pkt_ethernet, pkt_arp):
        self.arp_table[datapath.id][pkt_arp.src_ip] = (pkt_arp.src_mac, port)

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

    def send_packet_toDatapath(self, datapath, packet, port, dst_mac, src_mac):

        actions = [
            datapath.ofproto_parser.OFPActionSetField(eth_dst=src_mac),
            datapath.ofproto_parser.OFPActionSetField(eth_src=dst_mac),
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

        src_mac = pkt_ethernet.dst  # MAC DA INTERFACE DO ROUTER LIGADA AO SWITCH
        ip_src = self.dpidToIP.get(datapath.id,None)
        if src_mac is None or ip_src is None:
            return False
        if pkt_ipv4.dst == ip_src:
            pkt = self.build_icmp_packet(pkt_ethernet, pkt_ipv4, pkt_icmp, ip_src, src_mac)
            self._send_packet(datapath, port, pkt)
            return False
        return True

    def stripSubnetFromIP(self, ip):
        network = ipaddress.IPv4Network(ip + '/255.255.255.0', strict=False)
        return str(network.network_address)

    def build_icmp_packet(self, pkt_ethernet, pkt_ipv4, pkt_icmp, ip_src, src_mac):
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
        datapathip = self.dpidToIP.get(datapath.id)
        if datapathip is None:
            return
        datapathsubnet = self.stripSubnetFromIP(datapathip)
        tmpport = None
        mcdst = None
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                ipv4_dst=ip_dst)
        if subnet == datapathsubnet:
            out_port = self.portHelper[datapath.id]

            desc = self.arp_table[datapath.id].get(ip_dst, None)
            if desc is None:
                self.arpToGetLocation(datapath, pkt_ipv4, pkt)
                return
            else:
                mcdst, tmpport = desc
        else:
            final_dst = self.subnetToDpid.get(subnet, None)
            path = nx.shortest_path(self.net,datapath.id,final_dst)
            nextHop = path[path.index(datapath.id)+1]
            out_port = self.net[datapath.id][nextHop]['port']
            tmpport = out_port
            mcdst = self.topologyMacs[datapath.id][out_port]

        if out_port != ofproto.OFPP_FLOOD and mcdst is not None:
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

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for p in ev.msg.body:
            self.topologyMacs[dpid][p.port_no] = p.hw_addr

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        switches = [switch.dp.id for switch in self.topo_raw_switches]
        if self.topo_raw_links is not None:
            links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in self.topo_raw_links]
            self.net.add_edges_from(links)

        self.net.add_nodes_from(switches)

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """

    @set_ev_cls(event.EventLinkDelete, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_link_leave(self, ev):
        self.logger.info(f'link dropped')
        link = ev.link
        dst_link = link.dst
        src_link = link.src
        self.net.remove_edge(src_link.dpid,dst_link.dpid)
        flowToDelete = [(self.idToDataPath[dst_link.dpid]),(self.idToDataPath[src_link.dpid])]
        self.delete_flowWhenLinkDrop(flowToDelete)

    @set_ev_cls(event.EventLinkAdd, [MAIN_DISPATCHER])
    def handler_link_enter(self,ev):
        link = ev.link
        dst_link = link.dst
        src_link = link.src
        self.net.add_edge(src_link.dpid,dst_link.dpid)
        tmplst = [self.idToDataPath[src_link.dpid], self.idToDataPath[dst_link.dpid]]
        #self.delete_flowWhenLinkDrop(tmplst)

    """ def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        tmplst = list(self.topologyMacs[datapath.id].values())
        for dst in tmplst:
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)"""

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY, 0,
                                                      match, instructions)
        return flow_mod

    def remove_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                           empty_match, instructions)
        datapath.send_msg(flow_mod)

    def delete_flowWhenLinkDrop(self, mapdataPort):
        datapath= mapdataPort[0]
        datapathsrc = mapdataPort[1]
        self.remove_flows(datapath,0)
        self.remove_flows(datapathsrc,0)

