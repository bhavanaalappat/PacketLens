#pragma once
// main_window.h
//
// QMainWindow that owns:
//   • SnifferBackend  — capture & processing (background threads)
//   • ConnectionModel — data model for the table
//   • QTableView      — the visible grid
//   • QTimer          — fires every 1000 ms to pull a snapshot

#include <QMainWindow>
#include <QLabel>
#include <QTimer>
#include <memory>

class SnifferBackend;
class ConnectionModel;
class QTableView;
class QSortFilterProxyModel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    // Connected to QTimer::timeout — polls the backend for a snapshot
    // and refreshes the model in one batch.
    void onRefreshTimer();

    // Connected to SnifferBackend::newConnectionFound — used to update
    // the status bar instantly when a new process is resolved.
    void onNewConnection(QString srcIp, QString dstIp,
                         quint16 srcPort, quint16 dstPort,
                         QString protocol, QString process);

    // Connected to SnifferBackend::errorOccurred
    void onError(QString message);

private:
    void setupUi();
    void applyDarkStyle();

    SnifferBackend*          backend_    = nullptr;
    ConnectionModel*         model_      = nullptr;
    QSortFilterProxyModel*   proxy_      = nullptr;
    QTableView*              table_      = nullptr;
    QLabel*                  statusLbl_  = nullptr;
    QTimer*                  timer_      = nullptr;
};
