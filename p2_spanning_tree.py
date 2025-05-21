# p2_spanning_tree.py

from ryu.base import app_manager 
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link


class SpanningTreeSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Remove or correct the _CONTEXTS dictionary
    # It's unnecessary if we start Ryu with --observe-links
    # Alternatively, if you prefer to use _CONTEXTS, import the correct class
    from ryu.topology import switches
    _CONTEXTS = {'topology': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(SpanningTreeSwitch, self).__init__(*args, **kwargs)
        # MAC address to port mapping table: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Topology data structures
        self.datapaths = {}  # {dpid: datapath}
        self.ports = {}      # {dpid: {port_no: OFPPort}}
        self.adjacency = {}  # {(dpid1, dpid2): port_no}

        # Spanning tree data structures
        self.spanning_tree = set()  # set of edges (dpid1, dpid2) in spanning tree
        self.updating_port_config = False

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        """Handle switch enter event."""
        dpid = ev.switch.dp.id
        # if dpid in self.datapaths:
        #     self.logger.info(f"Switch {dpid} already known, skipping...")
        #     return  # Skip if switch is already known
        
        self.logger.info("Switch entered: %s", dpid)
        self.datapaths[dpid] = ev.switch.dp
        self.request_port_desc(ev.switch.dp)
        print("CASE1")
        self.update_topology()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        """Handle switch leave event."""
        self.logger.info("SWITCH LEFT : %s", ev.switch.dp.id)
        dpid = ev.switch.dp.id
        if dpid in self.datapaths:
            del self.datapaths[dpid]
        if dpid in self.ports:
            del self.ports[dpid]
        print("CASE2")
        self.update_topology()

    @set_ev_cls(topo_event.EventPortAdd)
    def port_add_handler(self, ev):
        """Handle port add event."""
        self.logger.info("Port added: %s %s", ev.port.dpid, ev.port.port_no)
        if dpid in self.ports and port_no in self.ports[dpid]:
        # Port already exists, skip update
            return
        self.request_port_desc(self.datapaths[ev.port.dpid])
        print("CASE3")
        self.update_topology()

    @set_ev_cls(topo_event.EventPortModify)
    def port_modify_handler(self, ev):
        """Handle port modify event."""
        if self.updating_port_config:
            return
        self.logger.info("Port modified: %s %s", ev.port.dpid, ev.port.port_no)
        self.request_port_desc(self.datapaths[ev.port.dpid])
        print("CASE4")
        self.update_topology()

    @set_ev_cls(topo_event.EventPortDelete)
    def port_delete_handler(self, ev):
        """Handle port delete event."""
        self.logger.info("Port deleted: %s %s", ev.port.dpid, ev.port.port_no)
        if ev.port.dpid in self.ports and ev.port.port_no in self.ports[ev.port.dpid]:
            del self.ports[ev.port.dpid][ev.port.port_no]
        print("CASE5")
        self.update_topology()

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        """Handle link add event."""
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no
        dst_port = ev.link.dst.port_no
        
        
        if (src_dpid, dst_dpid) in self.adjacency or (dst_dpid, src_dpid) in self.adjacency:  # Link already exists, skip update
            return
        self.adjacency[(src_dpid, dst_dpid)] = src_port
        self.adjacency[(dst_dpid, src_dpid)] = dst_port
        # self.logger.info(f"{src_dpid} <--> {dst_dpid}")
        print("CASE6")
        self.update_topology()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        """Handle link delete event."""
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid

        

        if (src_dpid, dst_dpid) in self.adjacency:
            del self.adjacency[(src_dpid, dst_dpid)]
        if (dst_dpid, src_dpid) in self.adjacency:
            del self.adjacency[(dst_dpid, src_dpid)]
        
        
        if ((src_dpid, dst_dpid) not in self.spanning_tree) and ((dst_dpid, src_dpid) not in self.spanning_tree):
            return

        print("CASE7")
        print(f"Updated adjacency after deletion: {self.adjacency}")
        self.update_topology()
        

    def request_port_desc(self, datapath):
        """Request port description to get port info."""
        ofproto = datapath.ofproto
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

    def update_topology(self):
        """Update the topology and compute the spanning tree."""
        self.logger.info("Updating topology")
        self.build_spanning_tree()
        self.configure_ports()
        self.print_spanning_tree()

    def build_spanning_tree(self):
        """Compute the spanning tree."""
        # Implement BFS to build spanning tree
        self.spanning_tree.clear()
        visited = set()
        if not self.datapaths:
            return
        root = min(self.datapaths.keys())  # Choose switch with smallest DPID as root

        queue = [root]
        visited.add(root)
        while queue:
            current = queue.pop(0)
            for neighbor in self.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    self.spanning_tree.add((current, neighbor))
                    self.spanning_tree.add((neighbor, current))  # For undirected graph
                    self.logger.info(f"{neighbor} and {current} added")
        print(self.adjacency)

    def get_neighbors(self, dpid):
        """Get neighboring switches of a switch."""
        neighbors = []
        for (src, dst) in self.adjacency:
            if src == dpid:
                neighbors.append(dst)
        return neighbors

    def configure_ports(self):
        """Configure ports to enable or disable forwarding based on spanning tree."""
        self.updating_port_config = True
        for dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            if dpid not in self.ports:
                continue
            for port_no in self.ports[dpid]:
                port = self.ports[dpid][port_no]
                if port_no > ofproto.OFPP_MAX:
                    continue  # Skip special ports
                if port_no == ofproto.OFPP_LOCAL:
                    continue  # Skip local port
                # Check if port is connected to another switch
                is_inter_switch_link = False
                for (src, dst) in self.adjacency:
                    if src == dpid and self.adjacency[(src, dst)] == port_no:
                        is_inter_switch_link = True
                        break
                if is_inter_switch_link:
                    # Check if this link is in the spanning tree
                    in_spanning_tree = False
                    if (dpid, dst) in self.spanning_tree:
                        in_spanning_tree = True
                    if in_spanning_tree:
                        # Ensure port is enabled
                        self.enable_port(datapath, port)
                    else:
                        # Disable port
                        self.disable_port(datapath, port)
                else:
                    # Port is connected to host, ensure port is enabled
                    self.enable_port(datapath, port)

        self.updating_port_config = False

    def disable_port(self, datapath, port):
        """Disable a port by setting OFPPC_NO_FWD."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        config = port.config | ofproto.OFPPC_NO_FWD
        mask = ofproto.OFPPC_NO_FWD

        port_mod = parser.OFPPortMod(datapath=datapath,
                                     port_no=port.port_no,
                                     hw_addr=port.hw_addr,
                                     config=config,
                                     mask=mask,
                                     advertise=port.advertised)
        datapath.send_msg(port_mod)
        self.logger.info("Disabled port %s on switch %s", port.port_no, datapath.id)

    def enable_port(self, datapath, port):
        """Enable a port by clearing OFPPC_NO_FWD."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        config = port.config & ~ofproto.OFPPC_NO_FWD
        mask = ofproto.OFPPC_NO_FWD


        port_mod = parser.OFPPortMod(datapath=datapath,
                                     port_no=port.port_no,
                                     hw_addr=port.hw_addr,
                                     config=config,
                                     mask=mask,
                                     advertise=port.advertised)
        datapath.send_msg(port_mod)
        self.logger.info("Enabled port %s on switch %s", port.port_no, datapath.id)

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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Helper function to add a flow entry to the switch."""
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

        # Ignore LLDP packets to avoid packet-in flood
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst  # Destination MAC
        src = eth.src  # Source MAC

        # Initialize MAC table for this switch
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("Packet in Switch %s: src=%s dst=%s in_port=%s", dpid, src, dst, in_port)

        # Learn the source MAC address to port mapping
        self.mac_to_port[dpid][src] = in_port

        # Determine the output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("Known destination: %s -> Port %s", dst, out_port)
            actions = [parser.OFPActionOutput(out_port)]
            # Install flow rule if destination is known
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            # Check if we have a valid buffer ID
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        else:
            # self.logger.info("Unknown destination: %s -> FLOOD", dst)

            ports = []
            if dpid in self.ports:
                for port_no in self.ports[dpid]:
                    if port_no != in_port:
                        port = self.ports[dpid][port_no]
                        # Check if port is enabled (not blocked)
                        if not port.config & ofproto.OFPPC_NO_FWD:
                            ports.append(port_no)
            # self.logger.info("Flooding out ports %s on Switch %s", ports, dpid)
            

            # Create actions for each port
            actions = [parser.OFPActionOutput(port) for port in ports]

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


    def print_spanning_tree(self):
        """Print the active connections in the spanning tree."""
        self.logger.info("Current Spanning Tree Connections:")
        if not self.spanning_tree:
            self.logger.info("No active connections in the spanning tree.")
            return

        l = [(min(a,b), max(a,b)) for (a,b) in self.spanning_tree]
        l = list(set(l))

        for edge in l:
            src, dst = edge
            self.logger.info(f"Connection: {src} <--> {dst}")