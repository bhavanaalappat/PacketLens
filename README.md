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
`CMakeLists.txt`        → Qt6 build definition, links `Qt6::Widgets`, `libpcap`, and `pthread`
`main.cpp`              → Qt application entry point, creates `MainWindow`
`main_window.cpp/h`     → Main GUI, tabs, refresh timer, backend orchestration
`sniffer_backend.cpp/h` → libpcap capture engine, worker thread, embedded HTTP API
`flow_manager.h`        → Flow lifecycle manager, thread-safe snapshots, garbage collection
`tcp_parser.cpp/h`      → Linux `/proc/net/tcp` socket-to-process resolution
`connection_model.cpp/h`→ Qt table model for active flow rows
`network_graph_widget.cpp/h` → Force-directed graph visualization for remote endpoints
`graph_node.cpp/h`      → Interactive graph nodes with hover cards and pinning
`side_panel.cpp/h`      → Clicked-node details inspector
`port_config.cpp/h`     → Human-editable port metadata from `ports.txt`
`http_api.cpp/h`        → Embedded REST API server serving `/flows`, `/stats`, `/health`
`packetlens_mcp.py`     → JSON-RPC stdio bridge for Claude Desktop / MCP integration
`ports.txt`             → Local port classification rules
`makefile`              → Minimal legacy build path for the non-Qt flow monitor

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

The bridge is intended to be launched by Claude Desktop via its MCP server configuration.

## Output

PacketLens produces:
* A live Qt GUI with a sortable flow table and an animated network graph
* In-app process and protocol metadata for active flows
* Embedded REST API responses on `127.0.0.1:8765`
* A local MCP bridge for assistant integration

### Example console output
Because PacketLens is a GUI application, it does not print a batch report. Instead, you should see:
* `[HttpApi] Listening on http://127.0.0.1:8765`
* GUI window with active flow counts
* API responses from `packetlens_mcp.py` when queried

## File Structure
.
├── CMakeLists.txt          # Qt6 build script and source list
├── makefile                # legacy minimal compile helper
├── main.cpp                # Qt application entry point
├── main_window.cpp/h       # UI shell, tabs, refresh timer, error handling
├── sniffer_backend.cpp/h   # Packet capture, worker thread, FlowManager, embedded HTTP API
├── flow_manager.h          # Thread-safe flow state manager
├── tcp_parser.cpp/h        # Linux socket parser for process attribution
├── connection_model.cpp/h  # Qt table model for active flows
├── network_graph_widget.cpp/h # Force-directed graph canvas for remote endpoints
├── graph_node.cpp/h        # Interactive graph node rendering and hover cards
├── side_panel.cpp/h        # Node selection detail panel
├── port_config.cpp/h       # Loads port labels and categories from `ports.txt`
├── http_api.cpp/h          # Embedded REST API implementation
├── packetlens_mcp.py       # Claude Desktop MCP stdio bridge
├── ports.txt               # User-editable port classification rules

## Design Decisions
*Qt + libpcap*: Qt gives a polished cross-platform desktop UI while `libpcap` provides stable packet capture.
*Embedded HTTP API*: A local REST endpoint makes PacketLens easy to script and integrate without an external service.
*Linux `/proc` socket mapping*: This delivers process labels for TCP flows, improving triage in the UI.
*Graph view + table view*: Users can switch between detailed flow rows and a high-level topological view.

## Caveats
* PacketLens currently targets IPv4 Ethernet capture and Linux-style `/proc` socket inspection.
* The embedded API is localhost-only by design.
* Elevated privileges are usually required for packet capture and process mapping.
* The graph visualization is designed for interactive monitoring, not for very large flow counts.
* `ports.txt` is loaded from the working directory; malformed lines are ignored.
