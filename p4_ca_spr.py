# p4_ca_spr.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp  # Import LLDP
from ryu.lib import hub
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link

import time

class CongestionAwareShortestPathSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    LLDP_SEND_INTERVAL = 1  # seconds between LLDP packets
    LLDP_TTL = 5            # Time to live for LLDP packets
    PATH_COMPUTE_INTERVAL = 10  # seconds between path computations

    CONGESTION_ALPHA = 0.7  # Weight factor for congestion in link cost

    def __init__(self, *args, **kwargs):
        super(CongestionAwareShortestPathSwitch, self).__init__(*args, **kwargs)
        # MAC address to port mapping table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Topology data structures
        self.datapaths = {}  # {dpid: datapath}
        self.ports = {}      # {dpid: {port_no: OFPPort}}
        self.adjacency = {}  # {dpid1: {dpid2: port_no}}

        # Network graph and paths
        self.graph = {}       # {dpid: {neighbor_dpid: cost}}
        self.link_delays = {} # {(dpid1, dpid2): delay}
        self.link_congestion = {}  # {(dpid1, dpid2): congestion_metric}
        self.paths = {}       # {src_dpid: {dst_dpid: previous_node}}

        # Host location mapping
        self.hosts = {}       # {mac: (dpid, port_no)}

        # ARP cache: {IP: (MAC, dpid, port_no)}
        self.arp_cache = {}   # {IP: (MAC, dpid, port_no)}

        # Set to track flooded packets
        self.flooded_packets = set()  # To track packets that have been flooded

        # Variables for port statistics
        self.port_stats = {}   # {dpid: {port_no: {stat_name: value}}}
        self.previous_port_stats = {}  # {dpid: {port_no: {stat_name: value}}}

        # Start LLDP and Path Computation threads
        self.lldp_thread = hub.spawn(self.lldp_loop)
        self.path_compute_thread = hub.spawn(self.path_compute_loop)

    def lldp_loop(self):
        """Periodic task to send LLDP packets."""
        while True:
            for dp in list(self.datapaths.values()):
                self.send_lldp_packets(dp)
            hub.sleep(self.LLDP_SEND_INTERVAL)

    def path_compute_loop(self):
        """Periodic task to compute shortest paths considering congestion."""
        while True:
            self.logger.info("Starting path computation...")
            self.request_port_stats()
            # Wait for port stats replies to be processed
            hub.sleep(1)  # Adjust sleep as needed to ensure stats are received

            self.compute_link_costs()
            self.compute_shortest_paths()
            self.install_all_paths()
            hub.sleep(self.PATH_COMPUTE_INTERVAL)

    def send_lldp_packets(self, datapath):
        """Send LLDP packets out of all ports."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dpid in self.ports:
            for port_no in self.ports[dpid]:
                if port_no <= ofproto.OFPP_MAX and port_no != ofproto.OFPP_LOCAL:
                    # Build LLDP packet with timestamp
                    pkt = self.build_lldp_packet(datapath, port_no)
                    data = pkt.data

                    actions = [parser.OFPActionOutput(port_no)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions,
                                              data=data)
                    datapath.send_msg(out)
        else:
            self.logger.debug("Ports not yet available for dpid %s", dpid)

    def build_lldp_packet(self, datapath, port_no):
        """Build LLDP packet with custom timestamp."""
        timestamp = time.time()

        # Chassis ID as bytes
        chassis_id_str = 'dpid:%016x' % datapath.id
        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=chassis_id_str.encode('utf-8')
        )

        # Port ID as bytes
        port_id_str = str(port_no)
        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_PORT_COMPONENT,
            port_id=port_id_str.encode('utf-8')
        )

        ttl = lldp.TTL(ttl=self.LLDP_TTL)

        # Timestamp as bytes
        sys_desc = lldp.SystemDescription(
            system_description=str(timestamp).encode('utf-8')
        )

        tlvs = (chassis_id, port_id, ttl, sys_desc, lldp.End())

        eth = ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_LLDP,
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src=datapath.ports[port_no].hw_addr
        )

        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()

        return pkt

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle datapath state changes."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.request_port_desc(datapath)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
            if datapath.id in self.adjacency:
                del self.adjacency[datapath.id]
            if datapath.id in self.ports:
                del self.ports[datapath.id]
            if datapath.id in self.port_stats:
                del self.port_stats[datapath.id]
            if datapath.id in self.previous_port_stats:
                del self.previous_port_stats[datapath.id]

    def request_port_desc(self, datapath):
        """Request port description to get port info."""
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """Handle port description reply."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.ports.setdefault(dpid, {})
        for p in ev.msg.body:
            self.ports[dpid][p.port_no] = p

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry to send unmatched packets to the controller."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath  # Keep track of datapaths
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match any packet
        match = parser.OFPMatch()

        # Actions: Send to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Create flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

        # Request port description
        self.request_port_desc(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets, learn MAC addresses, and install flow rules."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id  # Unique ID for the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        # Parse the incoming packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Handle LLDP packet
            self.handle_lldp_packet(msg, pkt)
            return

        dst = eth.dst  # Destination MAC
        src = eth.src  # Source MAC

        # Learn host location
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.hosts[src] = (dpid, in_port)  # Update hosts mapping

        # Learn host IP if it's an ARP packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocol(arp.arp)
            if pkt_arp:
                src_ip = pkt_arp.src_ip
                dst_ip = pkt_arp.dst_ip
                self.arp_cache[src_ip] = (src, dpid, in_port)
                if pkt_arp.opcode == arp.ARP_REQUEST:
                    self.handle_arp_request(msg, pkt_arp, src_mac=src, src_ip=src_ip, dst_ip=dst_ip)
                elif pkt_arp.opcode == arp.ARP_REPLY:
                    self.handle_arp_reply(msg, pkt_arp, src_mac=src, src_ip=src_ip)
                return

        # Install flows based on computed paths
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        elif dst in self.hosts:
            dst_dpid, dst_port = self.hosts[dst]
            path = self.get_path(dpid, dst_dpid)
            if path:
                self.install_path(path, src, dst)  # Ensure paths are installed here
                out_port = self.get_out_port(datapath, path, dpid, dst)
            else:
                self.flood_packet(msg, in_port)
                return
        else:
            self.flood_packet(msg, in_port)
            return

        actions = [parser.OFPActionOutput(out_port)]

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Create packet out message
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def handle_arp_request(self, msg, pkt_arp, src_mac, src_ip, dst_ip):
        """Handle incoming ARP requests."""
        self.arp_cache[src_ip] = (src_mac, msg.datapath.id, msg.match['in_port'])
        self.hosts[src_mac] = (msg.datapath.id, msg.match['in_port'])
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Check if the controller knows the MAC for dst_ip
        if dst_ip in self.arp_cache:
            dst_mac, dst_dpid, dst_port = self.arp_cache[dst_ip]
            self.logger.info("Responding to ARP request for %s with MAC %s", dst_ip, dst_mac)
            arp_reply = packet.Packet()
            arp_reply.add_protocol(
                ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=src_mac,
                    src=dst_mac
                )
            )
            arp_reply.add_protocol(
                arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=dst_mac,
                    src_ip=dst_ip,
                    dst_mac=src_mac,
                    dst_ip=src_ip
                )
            )
            arp_reply.serialize()

            # Send ARP reply
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=arp_reply.data
            )
            datapath.send_msg(out)

            # Install path between src and dst
            path = self.get_path(dpid, dst_dpid)
            if path:
                self.install_path(path, src_mac, dst_mac)
        else:
            # Flood the ARP request if destination MAC unknown
            self.flood_packet(msg, in_port)

    def handle_arp_reply(self, msg, pkt_arp, src_mac, src_ip):
        """Handle incoming ARP replies."""
        # Update ARP cache
        self.arp_cache[src_ip] = (src_mac, msg.datapath.id, msg.match['in_port'])
        self.hosts[src_mac] = (msg.datapath.id, msg.match['in_port'])
        self.logger.info("Received ARP reply: %s is at %s", src_ip, src_mac)

    def flood_packet(self, msg, in_port):
        """Flood the packet out of all ports except the input port."""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Generate a unique identifier for the packet to track it
        # For ARP packets, we can use (ethertype, src_ip, dst_ip)
        # For other packets, you can adjust accordingly
        pkt_id = None
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            pkt_id = (eth.ethertype, arp_pkt.src_ip, arp_pkt.dst_ip)
        else:
            # For other types, you can define pkt_id based on your needs
            pkt_id = (eth.ethertype, eth.src, eth.dst)

        if pkt_id in self.flooded_packets:
            # Drop the packet if it has been flooded before
            self.logger.debug("Dropping packet %s as it has been flooded before.", pkt_id)
            return
        else:
            # Mark the packet as flooded
            self.flooded_packets.add(pkt_id)
            self.logger.debug("Flooding packet %s.", pkt_id)

        if datapath.id in self.ports:
            out_ports = [port_no for port_no in self.ports[datapath.id]
                         if port_no != in_port and port_no <= ofproto.OFPP_MAX]
            actions = [parser.OFPActionOutput(port_no) for port_no in out_ports]
        else:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def handle_lldp_packet(self, msg, pkt):
        """Process received LLDP packet to measure link delay."""
        dpid = msg.datapath.id
        in_port = msg.match['in_port']

        lldp_pkt = pkt.get_protocol(lldp.lldp)
        if lldp_pkt is None:
            return

        # Extract source DPID from Chassis ID
        chassis_id = lldp_pkt.tlvs[0].chassis_id.decode('utf-8')

        if chassis_id.startswith('dpid:'):
            src_dpid = int(chassis_id[5:], 16)
        else:
            self.logger.error("Invalid chassis ID format: %s", chassis_id)
            return

        # Extract source port from Port ID
        port_id = lldp_pkt.tlvs[1].port_id.decode('utf-8')

        try:
            src_port_no = int(port_id)
        except ValueError:
            self.logger.error("Invalid port ID format: %s", port_id)
            return

        # Extract timestamp from System Description field
        timestamp_str = lldp_pkt.tlvs[3].system_description.decode('utf-8')
        try:
            timestamp = float(timestamp_str)
        except ValueError:
            self.logger.error("Invalid timestamp format: %s", timestamp_str)
            return

        delay = time.time() - timestamp

        # Update link delay
        self.link_delays[(src_dpid, dpid)] = delay
        self.logger.info("Link delay from %s to %s: %f", src_dpid, dpid, delay)

        # Update adjacency
        self.adjacency.setdefault(src_dpid, {})[dpid] = src_port_no
        self.adjacency.setdefault(dpid, {})[src_dpid] = in_port

        # Recompute shortest paths
        # Note: Path computation is handled in the periodic path_compute_loop
        # So no need to compute it here

    def request_port_stats(self):
        """Request port statistics from all switches."""
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply and compute congestion metrics."""
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        self.port_stats.setdefault(dpid, {})
        self.previous_port_stats.setdefault(dpid, {})

        for stat in sorted(body, key=lambda x: x.port_no):
            port_no = stat.port_no

            # Skip ports that are not part of the adjacency (i.e., host ports)
            if dpid not in self.adjacency or port_no not in self.adjacency[dpid]:
                continue

            # Initialize previous stats if not present
            if port_no not in self.previous_port_stats[dpid]:
                self.previous_port_stats[dpid][port_no] = {
                    'tx_packets': stat.tx_packets,
                    'tx_dropped': stat.tx_dropped,
                    # Add other stats if needed
                }
                continue

            # Calculate delta
            prev_stats = self.previous_port_stats[dpid][port_no]
            delta_tx_packets = stat.tx_packets - prev_stats['tx_packets']
            delta_tx_dropped = stat.tx_dropped - prev_stats['tx_dropped']

            # Update previous stats
            self.previous_port_stats[dpid][port_no]['tx_packets'] = stat.tx_packets
            self.previous_port_stats[dpid][port_no]['tx_dropped'] = stat.tx_dropped

            # Define congestion metric
            # For simplicity, using the number of dropped packets as congestion
            congestion = delta_tx_dropped

            # Alternatively, you could use delta_tx_packets to estimate load
            # congestion = delta_tx_packets

            # Update congestion metric for the link
            # Assuming (dpid, neighbor_dpid)
            neighbor_dpid = None
            for neighbor, port in self.adjacency[dpid].items():
                if port == port_no:
                    neighbor_dpid = neighbor
                    break
            if neighbor_dpid is not None:
                self.link_congestion[(dpid, neighbor_dpid)] = congestion
                self.logger.info("Link congestion from %s to %s: %d", dpid, neighbor_dpid, congestion)

    def compute_link_costs(self):
        """Compute link costs based on delay and congestion."""
        for src in self.adjacency:
            for dst in self.adjacency[src]:
                # Get delay
                delay = self.link_delays.get((src, dst), 1)  # Default delay if not measured

                # Get congestion
                congestion = self.link_congestion.get((src, dst), 0)  # Default no congestion

                # Compute cost as delay + alpha * congestion
                cost = delay + self.CONGESTION_ALPHA * congestion

                # Update graph
                self.graph.setdefault(src, {})[dst] = cost

        self.logger.info("Updated link costs based on delay and congestion.")

    def compute_shortest_paths(self):
        """Compute shortest paths from every switch to every other switch."""
        self.paths.clear()
        for src in self.graph:
            distances, previous = self.dijkstra(src)
            self.paths[src] = previous
        self.logger.info("Computed shortest paths based on updated link costs.")

    def build_graph(self):
        """Build the network graph with measured delays and congestion."""
        # This function is now integrated into compute_link_costs
        pass  # No longer needed

    def dijkstra(self, src):
        """Compute shortest paths from src using Dijkstra's algorithm."""
        distances = {node: float('inf') for node in self.graph}
        previous = {node: None for node in self.graph}
        distances[src] = 0
        Q = set(self.graph.keys())

        while Q:
            u = min(Q, key=lambda node: distances[node])
            Q.remove(u)
            if distances[u] == float('inf'):
                break
            for v in self.graph[u]:
                alt = distances[u] + self.graph[u][v]
                if alt < distances[v]:
                    distances[v] = alt
                    previous[v] = u
        return distances, previous

    def get_path(self, src_dpid, dst_dpid):
        """Retrieve the shortest path from src_dpid to dst_dpid."""
        path = []
        if src_dpid == dst_dpid:
            path = [src_dpid]
        elif src_dpid in self.paths:
            node = dst_dpid
            while node != src_dpid:
                if node is None:
                    return []
                path.insert(0, node)
                node = self.paths[src_dpid].get(node, None)
            path.insert(0, src_dpid)
        return path

    def install_all_paths(self):
        """Install flow entries for all computed paths."""
        for src in self.paths:
            for dst in self.paths[src]:
                if src == dst:
                    continue
                path = self.get_path(src, dst)
                if path:
                    # Find host MAC addresses associated with dst switch
                    dst_hosts = [mac for mac, location in self.hosts.items() if location[0] == dst]
                    for dst_mac in dst_hosts:
                        # Find all hosts on the dst switch
                        self.install_path(path, None, dst_mac)
        self.logger.info("Installed all computed paths.")

    def install_path(self, path, src_mac, dst_mac):
        """Install flow entries along the path for specific src and dst MAC addresses."""
        if not path:
            return

        # If src_mac is None, this is a broadcast or non-specific flow
        # For simplicity, we'll assume src_mac and dst_mac are provided
        if src_mac is None or dst_mac is None:
            return

        # Install flows from src to dst
        for i in range(len(path)-1):
            src_dp = self.datapaths[path[i]]
            out_port = self.adjacency[path[i]][path[i+1]]
            match = src_dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [src_dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(src_dp, 1, match, actions)

        # Install flows from dst to src (reverse path)
        rev_path = list(reversed(path))
        for i in range(len(rev_path)-1):
            src_dp = self.datapaths[rev_path[i]]
            out_port = self.adjacency[rev_path[i]][rev_path[i+1]]
            match = src_dp.ofproto_parser.OFPMatch(eth_src=dst_mac, eth_dst=src_mac)
            actions = [src_dp.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(src_dp, 1, match, actions)

        # Finally, set the output port on the destination switch to the host
        dst_dp = self.datapaths[path[-1]]
        dst_out_port = self.mac_to_port[dst_dp.id].get(dst_mac, None)
        if dst_out_port:
            match = dst_dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [dst_dp.ofproto_parser.OFPActionOutput(dst_out_port)]
            self.add_flow(dst_dp, 1, match, actions)

    def get_out_port(self, datapath, path, dpid, dst_mac):
        """Get the output port for the next hop in the path."""
        index = path.index(dpid)
        if index < len(path) - 1:
            next_hop = path[index + 1]
            out_port = self.adjacency[dpid][next_hop]
        else:
            # Last switch, send to host
            out_port = self.mac_to_port[dpid].get(dst_mac, None)
        return out_port

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Instructions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Create flow mod message
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
