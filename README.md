# SDN Ryu Routing Repo

This repository presents a comprehensive implementation of various controller applications using the Ryu SDN framework to manage OpenFlow-based networks. These applications simulate real-world behaviors in network switches and demonstrate key principles of Software-Defined Networking (SDN), such as centralized control, dynamic routing, loop prevention, and congestion awareness.


## Contents

The repository includes Python controller scripts and a detailed report describing implementation strategies, observations, and results.

### Files

- `p1_hub.py` - Hub-based forwarding controller.
- `p1_learning.py` - MAC learning switch controller.
- `p2_spanning_tree.py` - Spanning Tree Protocol controller to avoid broadcast loops.
- `p3_spr.py` - Static Shortest Path Routing controller based on link delay.
- `p4_ca_spr.py` - Congestion-Aware Shortest Path Routing controller using live port stats.
- `report.pdf` - Detailed explanation of implementation methods, assumptions, test results, and performance analysis.

## Technologies Used

- Ryu Controller (Python)
- OpenFlow v1.3
- Mininet Network Emulator
- Linux (Ubuntu recommended)

## Installation Instructions

### 1. Environment Setup

- Install Mininet:
  ```bash
  sudo apt-get update
  sudo apt-get install mininet
  ```

- Install Ryu Controller:
  ```bash
  pip install ryu
  ```

- Install required system packages (if needed for Mininet xterm):
  ```bash
  sudo apt-get install xterm
  ```

### 2. Running a Controller Application

```bash
ryu-manager <controller_script>.py
```

Example:
```bash
ryu-manager p3_spr.py
```

### 3. Launching a Custom Topology in Mininet

```bash
sudo mn --custom topology.py --topo mytopo --controller=remote
```

Ensure `topology.py` defines the required topology used in the assignment (e.g., tree, cycle, etc.).

## Functional Overview

### Part 1: Hub and Learning Switch

- **Hub Controller (`p1_hub.py`)**
  - Forwards every incoming packet to all ports except the one it arrived on.
  - Simulates a legacy Ethernet hub.
  - No MAC learning; leads to broadcast overhead.
  - Very low throughput due to redundant packet flooding.

- **Learning Switch (`p1_learning.py`)**
  - Learns MAC-to-port mappings from incoming packets.
  - Installs flow rules in switches for known destinations.
  - Significantly improves throughput and scalability.

### Part 2: Spanning Tree Protocol (`p2_spanning_tree.py`)

- Prevents broadcast storms in cyclic Layer 2 topologies.
- Builds a logical loop-free topology using Breadth-First Search (BFS).
- Maintains an adjacency matrix and blocks redundant links.
- Only ports on the spanning tree are allowed to forward broadcast packets.
- Assumes the switch with the lowest DPID as the root of the tree.
- Recomputes the tree on topology changes.

### Part 3: Shortest Path Routing (`p3_spr.py`)

- Performs dynamic path computation using Dijkstra’s algorithm.
- Uses link delay as the edge weight to select optimal paths.
- Maintains a topology graph based on probe measurements.
- Installs bidirectional flow rules for efficient data forwarding.
- Handles ARP resolution and unknown hosts via controlled flooding.

### Part 4: Congestion-Aware Shortest Path Routing (`p4_ca_spr.py`)

- Enhances the shortest path routing by factoring in congestion.
- Uses LLDP for link delay estimation and OpenFlow port stats for congestion.
- Computes cost as:

```
Cost(link) = Delay(link) + alpha * Congestion(link)
```

- Periodically updates path calculations to reflect network load.
- Reduces usage of highly congested paths in real-time.
- Demonstrates dynamic re-routing capabilities of SDN.

## Testing and Evaluation

### Functional Tests

- `pingall` - Test network connectivity.
- `iperf` - Measure throughput between specific hosts (e.g., h1 and h5).
- `dpctl dump-flows` - Inspect flow entries on switches.

### Performance Metrics

- Throughput comparison between hub and learning switch.
- Flow table analysis for all controller types.
- Loop elimination using STP.
- Path optimality and adaptivity in congestion-aware routing.

## Assumptions

- Topology remains stable during delay or congestion measurement.
- Controller receives timely and accurate topology events.
- All switches are OpenFlow-compatible and responsive.
- Hosts are directly connected to switches.
- LLDP and port statistics reliably represent delay and congestion.

## Report

See `report.pdf` for:
- Implementation details for each controller.
- Screenshots of flow tables and command outputs.
- Detailed performance analysis and observations.
- Mathematical modeling of flow table entries and path computation logic.


