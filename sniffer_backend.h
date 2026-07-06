#pragma once
// sniffer_backend.h  (updated — adds embedded HTTP API)

#include <QObject>
#include <QString>
#include <QStringList>
#include <memory>
#include <thread>
#include <atomic>
#include <vector>

#include "flow_manager.h"
#include "http_api.h"

class TcpParser;

class SnifferBackend : public QObject {
    Q_OBJECT

public:
    struct CaptureInterface {
        QString name;
        QString description;
    };

    explicit SnifferBackend(QObject* parent = nullptr);
    ~SnifferBackend() override;

    static std::vector<CaptureInterface> availableInterfaces(QString* error = nullptr);

    bool start(const QStringList& interfaces = {});
    void stop();

    std::vector<FlowSnapshot> snapshot() const { return manager_.get_snapshot(); }

    uint64_t totalPackets() const { return const_cast<FlowManager&>(manager_).total_packets(); }
    uint64_t totalBytes()   const { return const_cast<FlowManager&>(manager_).total_bytes();   }

    // Port the HTTP API is listening on (0 if not started yet)
    uint16_t apiPort() const { return httpApi_ ? httpApi_->port() : 0; }

signals:
    void newConnectionFound(QString srcIp, QString dstIp,
                            quint16 srcPort, quint16 dstPort,
                            QString protocol, QString process);
    void errorOccurred(QString message);

private:
    void snifferThread(void* handle);
    void workerThread();
    void cleanupThread();  // Active timeout-based cleanup thread

    mutable FlowManager manager_;

    std::vector<void*> pcap_handles_;

    struct RawPacket;
    struct PacketQueue;
    std::unique_ptr<PacketQueue> queue_;

    std::vector<std::thread> sniffer_threads_;
    std::thread worker_thread_;
    std::thread cleanup_thread_;   // ← Active cleanup thread
    std::atomic<bool> running_{ false };

    // Embedded HTTP REST API
    std::unique_ptr<HttpApi> httpApi_;
    static constexpr uint16_t HTTP_API_PORT = 8765;
};
