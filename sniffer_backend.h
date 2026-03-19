#pragma once
// sniffer_backend.h
//
// Runs the libpcap capture loop and packet-processing worker on two
// background std::threads.  Lives in the Qt main thread as a QObject so
// its signals safely cross the thread boundary to any slot connected
// with Qt::QueuedConnection (the default for cross-thread connects).

#include <QObject>
#include <QString>
#include <memory>
#include <thread>
#include <atomic>

#include "flow_manager.h"

// Forward-declared so tcp_parser.h is not required by GUI translation units.
class TcpParser;

// ─────────────────────────────────────────────────────────────────────────────
class SnifferBackend : public QObject {
    Q_OBJECT

public:
    explicit SnifferBackend(QObject* parent = nullptr);
    ~SnifferBackend() override;

    // Start capture on the first available interface (must be root).
    // Returns true on success.
    bool start();

    // Request a graceful shutdown of capture/worker threads.
    void stop();

    // Called by the GUI timer — returns a thread-safe snapshot of the
    // current flow table.  No signal/slot overhead, just a direct call
    // from the main thread.
    std::vector<FlowSnapshot> snapshot() const { return manager_.get_snapshot(); }

    uint64_t totalPackets() const { return const_cast<FlowManager&>(manager_).total_packets(); }
    uint64_t totalBytes()   const { return const_cast<FlowManager&>(manager_).total_bytes();   }

signals:
    // Emitted from the worker thread whenever a process name is resolved for
    // a new flow.  Qt marshals this through its event loop automatically when
    // connected with Qt::QueuedConnection.
    void newConnectionFound(QString srcIp, QString dstIp,
                            quint16 srcPort, quint16 dstPort,
                            QString protocol, QString process);

    // Emitted when the backend encounters a fatal error (e.g., pcap open fails).
    void errorOccurred(QString message);

private:
    // The two worker threads — created on start(), joined on stop().
    void snifferThread();
    void workerThread();

    // Shared state
    mutable FlowManager manager_;

    // libpcap handle — opaque pointer to avoid pulling in pcap.h here
    void*              pcap_handle_  = nullptr;

    // Packet queue between sniffer and worker threads
    struct RawPacket;
    struct PacketQueue;
    std::unique_ptr<PacketQueue> queue_;

    std::thread sniffer_thread_;
    std::thread worker_thread_;
    std::atomic<bool> running_{ false };
};
