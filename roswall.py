# TODO: update
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp 
from ryu.lib.packet import icmp
from ryu.lib.packet import packet_utils


class ROSWall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ROSWall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Current internal representation of the ROS system
        self.ros_state_table = {}
        # Permissions for the ROS system. A dict of permissions objects. Abstract
        self.ros_permissions_table = {} 
        # Permissions for the Robot itself, designed for things like ssh. 
        self.port_permissions_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        t=time.time()
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            elasped = time.time()-t
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if arp_pkt:
            data = msg.data
            self.logger.info("Intercepted ARP packet with source port {} and dest port {}".format(arp_pkt.src_mac, arp_pkt.dst_mac))
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                arp_sha=arp_pkt.src_mac, arp_tha=arp_pkt.dst_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.logger.info("Adding ARP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elapsed = time.time()-t
                print("Duration " + str(elapsed))
                return
            else:
                self.logger.info("Adding ARP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions)
            datapath.send_msg(out)
            return 

        elif icmp_pkt:
            data = msg.data
            self.logger.info("Intercepted ICMP packet with type {}".format(icmp_pkt.type))
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                ip_proto=ipv4_pkt.proto, icmpv4_type=icmp_pkt.type,
                ipv4_dst=ipv4_pkt.dst, ipv4_src=ipv4_pkt.src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.logger.info("Adding ICMP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elapsed = time.time()-t
                print("Duration " + str(elapsed))
                return
            else:
                self.logger.info("Adding ICMP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions)
            datapath.send_msg(out)
            return 
        elif tcp_pkt:
            data = msg.data
            self.logger.info("Intercepted TCP packet with source port {} and dest port {}".format(tcp_pkt.src_port, tcp_pkt.dst_port))
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                ip_proto=ipv4_pkt.proto, tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
                ipv4_dst=ipv4_pkt.dst, ipv4_src=ipv4_pkt.src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.logger.info("Adding TCP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elapsed = time.time()-t
                print("Duration " + str(elapsed))
                return
            else:
                self.logger.info("Adding TCP FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions)
            datapath.send_msg(out)
            return 
        elif ipv4_pkt:
            data = msg.data
            self.logger.info("Intercepted Generic packet with source port {} and dest port {}".format(ipv4_pkt.src, ipv4_pkt.dst))
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                ip_proto=ipv4_pkt.proto, ipv4_src=ipv4_pkt.src, ipv4_dst=ipv4_pkt.dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.logger.info("Adding GENERIC FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elapsed = time.time()-t
                print("Duration " + str(elapsed))
                return
            else:
                self.logger.info("Adding GENERIC FLOW NOW PLZ")
                self.add_flow(datapath, 1, match, actions)
            datapath.send_msg(out)
            return 

        # install a flow to avoid packet_in next time
        elif out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
             #verify if we have a valid buffer_id, if yes avoid to send both
             #flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elasped = time.time()-t
                print("Duration " + str(elapsed))
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
