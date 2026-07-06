#pragma once
// main_window.h  (updated — v2 with graph view)
//
// QMainWindow that owns:
//   • SnifferBackend      — capture & processing (background threads)
//   • ConnectionModel     — data model for the table view
//   • NetworkGraphWidget  — force-directed graph canvas
//   • SidePanel           — node-detail inspector
//   • QTabWidget          — switches between Table and Graph views
//   • QTimer              — fires every 1000 ms to pull a snapshot

#include <QMainWindow>
#include <QLabel>
#include <QTimer>
#include <QStringList>

#include "flow_manager.h"

class SnifferBackend;
class ConnectionModel;
class NetworkGraphWidget;
class SidePanel;
class QTableView;
class QSortFilterProxyModel;
class QTabWidget;
class QSplitter;
class QPushButton;
class QComboBox;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void onRefreshTimer();
    void onNewConnection(QString srcIp, QString dstIp,
                         quint16 srcPort, quint16 dstPort,
                         QString protocol, QString process);
    void onError(QString message);
    void onNodeSelected(QString ip, uint64_t bytes, uint64_t packets,
                        QString process, quint16 port, QString state);
    void onHostSelected(QString host, QString ip, uint64_t bytes,
                        uint64_t packets, uint64_t flows);
    void onChooseInterfaces();
    void onHostFilterChanged();

private:
    void setupUi();
    void applyDarkStyle();
    void initializeInterfaces();
    bool startCaptureWithInterfaces(const QStringList& interfaces);
    void updateInterfaceButton();
    QString interfaceSummary() const;
    void updateHostFilter(const std::vector<FlowSnapshot>& snapshot);
    std::vector<FlowSnapshot> applyHostFilter(const std::vector<FlowSnapshot>& snapshot) const;

    SnifferBackend*        backend_    = nullptr;
    ConnectionModel*       model_      = nullptr;
    QSortFilterProxyModel* proxy_      = nullptr;
    QTableView*            table_      = nullptr;
    QLabel*                statusLbl_  = nullptr;
    QPushButton*           ifaceBtn_   = nullptr;
    QComboBox*             hostFilter_ = nullptr;
    QTimer*                timer_      = nullptr;
    QStringList            selectedInterfaces_;

    // Graph view components
    NetworkGraphWidget*    graphWidget_ = nullptr;
    SidePanel*             sidePanel_   = nullptr;
    QSplitter*             graphSplit_  = nullptr;

    QTabWidget*            tabs_        = nullptr;
};
