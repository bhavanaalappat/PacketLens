# PacketLens

Real-time Visual Network Flow Monitor with Embedded API and MCP Bridge

## The Problem
Local network flow visibility is fragmented.
* Packet capture tools often expose raw packets, not flow state or process ownership.
* Security and troubleshooting workflows need both table-based flow inspection and a live, intuitive graph view.
* Local observability suffers from poor integration with external assistants or automation tools.

## Our Solution
PacketLens is a desktop application that captures TCP/UDP traffic, reconstructs active connections, attributes flows to local processes where possible, and presents the data in both a sortable table and an animated network graph. It also exposes a lightweight embedded HTTP API so external tools can query live flow snapshots, statistics, and health status.

## Architecture

| Component | Responsibility |
|-----------|----------------|
| `main.cpp` | Qt application entry point; initializes the application and creates the `MainWindow`. |
| `MainWindow` (`main_window.cpp/h`) | Coordinates the UI, refresh timer, tab management, and communication with the backend. |
| `SnifferBackend` (`sniffer_backend.cpp/h`) | Captures packets using `libpcap`, processes them on a worker thread, updates active flows, and integrates the embedded HTTP API. |
| `FlowManager` (`flow_manager.h`) | Maintains thread-safe flow state, aggregates statistics, provides snapshots, and removes stale flows. |
| `TCPParser` (`tcp_parser.cpp/h`) | Resolves Linux TCP sockets to their owning processes using `/proc/net/tcp` and `/proc`. |
| `ConnectionModel` (`connection_model.cpp/h`) | Qt table model that supplies active network flow data to the Connections view. |
| `NetworkGraphWidget` (`network_graph_widget.cpp/h`) | Renders an interactive force-directed graph of remote endpoints and active connections. |
| `GraphNode` (`graph_node.cpp/h`) | Implements interactive graph nodes with hover cards, selection, and pinning. |
| `SidePanel` (`side_panel.cpp/h`) | Displays detailed information for the currently selected graph node. |
| `PortConfig` (`port_config.cpp/h`) | Loads user-defined port names and categories from `ports.txt`. |
| `HttpApi` (`http_api.cpp/h`) | Embedded REST API server exposing `/flows`, `/stats`, and `/health` endpoints. |
| `packetlens_mcp.py` | Model Context Protocol (MCP) bridge that streams PacketLens data to AI assistants such as Claude Desktop. |
| `CMakeLists.txt` | Defines the Qt6 build configuration, dependencies, and compilation targets. |
| `ports.txt` | User-editable port classification and labeling rules. |

## How It Works

### Packet Capture and Flow Reconstruction
`SnifferBackend` opens a live `libpcap` capture on the first available interface and applies a `tcp or udp` BPF filter.
* `snifferThread()` receives raw Ethernet/IP packets and pushes them into a thread-safe queue.
* `workerThread()` consumes packets, validates IPv4/TCP/UDP headers, constructs canonical `FlowKey` tuples, and updates the `FlowManager`.
* TCP state is inferred from SYN/FIN/RST flags; UDP flows are tracked until timeout.

### Process Attribution
`TcpParser` reads `/proc/net/tcp` and maps active socket inodes back to local process IDs.
* If a matching socket exists, `SnifferBackend` resolves the PID and process name from `/proc/<pid>/comm` or `/proc/<pid>/cmdline`.
* This enables PacketLens to label flows with the owning process when available.

### Flow State Management
`FlowManager` maintains a thread-safe hash map of active flows.
* Each flow tracks bytes, packets, last-seen timestamp, TCP state, and process metadata.
* Periodic garbage collection removes stale connections after TCP/UDP timeouts.
* `get_snapshot()` returns a consistent vector of `FlowSnapshot` rows for the UI and API.

### User Interface
`MainWindow` builds a dark-themed Qt interface with two main tabs:
1. `Flow Table` — sortable, filterable table of active flows.
2. `Network Graph` — animated force-directed view of remote endpoints around a central master node.

Every second, the UI refreshes from the backend snapshot:
* `ConnectionModel::refresh()` rebuilds the table rows.
* `NetworkGraphWidget::updateFromSnapshot()` updates or creates graph nodes, edges, and flow metadata.
* Clicking a remote node populates `SidePanel` with IP, bytes, packets, process, port, and state.

### Embedded HTTP API
`HttpApi` listens on `127.0.0.1:8765` and exposes:
* `GET /health` — returns `{"status":"ok"}`
* `GET /flows` — returns a JSON array of active flow snapshots
* `GET /stats` — returns aggregate packet, byte, and flow totals

This API is intentionally local-only and lightweight so PacketLens can be queried by other tools without requiring a separate server process.

### MCP Bridge
`packetlens_mcp.py` is a Python stdin/stdout JSON-RPC wrapper for Claude Desktop.
* It speaks the MCP protocol on stdin/stdout.
* It queries PacketLens via the embedded HTTP API.
* It exposes commands such as `get_flows`, `get_stats`, `get_top_talkers`, and `check_health`.

## Configuration

### Build and Runtime
* The Qt application is built with `CMakeLists.txt`.
* `makefile` offers a legacy minimal build path for `side.cpp` and `tcp_parser.cpp`.
* `ports.txt` is loaded at startup and can be edited while PacketLens is not running.
* The embedded API default port is `8765`.
* The UI refreshes every second.

### Port Classification
`ports.txt` defines port labels and categories:
* `danger` — legacy or unencrypted protocols
* `secure` — encrypted or authenticated services
* `caution` — infrastructure/databases

The port categories are used for UI colour hints in the graph and side panel.

## Installation

Prerequisites:
* Qt 6 development libraries (`Qt6::Widgets`)
* `libpcap` development headers
* `cmake` and a C++17-capable compiler
* Python 3.x for `packetlens_mcp.py`

On macOS / Linux, install the required packages for your platform, then build:

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

Or use the legacy makefile for the simple CLI/engine target:

```bash
make
```

## Usage

Run the Qt desktop app:

```bash
sudo ./packetlens
```

> Root or elevated privileges are typically required for live `libpcap` capture and Linux `/proc` socket inspection.

Run the MCP bridge separately while PacketLens is already running:

```bash
python3 packetlens_mcp.py
```

The bridge is intended to be launched by AI tools via its MCP server configuration.



| Decision | Rationale |
|----------|-----------|
| Qt + `libpcap` | Native desktop interface with efficient packet capture. |
| Embedded HTTP API | Enables scripting and external integrations. |
| `/proc` socket mapping | Associates flows with local processes. |
| Graph + Table views | Supports both overview and detailed inspection. |

## Caveats
* PacketLens currently targets IPv4 Ethernet capture and Linux-style `/proc` socket inspection.
* The embedded API is localhost-only by design.
* Elevated privileges are usually required for packet capture and process mapping.
* The graph visualization is designed for interactive monitoring, not for very large flow counts.
* `ports.txt` is loaded from the working directory; malformed lines are ignored.
