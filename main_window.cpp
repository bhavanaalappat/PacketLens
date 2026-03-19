// main_window.cpp
#include "main_window.h"
#include "sniffer_backend.h"
#include "connection_model.h"

#include <QApplication>
#include <QTableView>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QTimer>
#include <QSortFilterProxyModel>
#include <QLineEdit>
#include <QStatusBar>
#include <QMessageBox>
#include <QPalette>
#include <QFont>
#include <QFrame>

// ── Constructor ───────────────────────────────────────────────────────────────
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("PacketLens — Network Flow Monitor");
    resize(1280, 720);

    applyDarkStyle();
    setupUi();

    // ── Wire signals ──────────────────────────────────────────────────────────
    // newConnectionFound is emitted from the worker thread.
    // Qt::QueuedConnection (the default for cross-thread connects) ensures
    // the slot runs on the main thread even though the signal was emitted
    // from a background std::thread.
    connect(backend_, &SnifferBackend::newConnectionFound,
            this,     &MainWindow::onNewConnection,
            Qt::QueuedConnection);

    connect(backend_, &SnifferBackend::errorOccurred,
            this,     &MainWindow::onError,
            Qt::QueuedConnection);

    // ── QTimer: pull a snapshot every second ──────────────────────────────────
    // The timer fires on the main (GUI) thread; no mutex needed by the caller
    // because FlowManager::get_snapshot() is internally mutex-guarded.
    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &MainWindow::onRefreshTimer);
    timer_->start(1000); // 1 000 ms = 1 s

    // ── Start capture ─────────────────────────────────────────────────────────
    if (!backend_->start()) {
        // errorOccurred will have been emitted; the slot will show a dialog.
    }
}

MainWindow::~MainWindow() {
    timer_->stop();
    backend_->stop();
}

// ── UI construction ───────────────────────────────────────────────────────────
void MainWindow::setupUi() {
    // Central widget
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* vLayout = new QVBoxLayout(central);
    vLayout->setContentsMargins(8, 8, 8, 4);
    vLayout->setSpacing(6);

    // ── Header bar ────────────────────────────────────────────────────────────
    auto* headerFrame = new QFrame;
    headerFrame->setObjectName("headerFrame");
    auto* hLayout = new QHBoxLayout(headerFrame);
    hLayout->setContentsMargins(8, 4, 8, 4);

    auto* title = new QLabel("🔬 PacketLens");
    title->setObjectName("titleLabel");

    auto* search = new QLineEdit;
    search->setObjectName("searchBox");
    search->setPlaceholderText("Filter (IP, process, state…)");
    search->setMaximumWidth(280);

    statusLbl_ = new QLabel("Starting…");
    statusLbl_->setObjectName("statusLabel");
    statusLbl_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    hLayout->addWidget(title);
    hLayout->addStretch();
    hLayout->addWidget(search);
    hLayout->addSpacing(12);
    hLayout->addWidget(statusLbl_);

    vLayout->addWidget(headerFrame);

    // ── Table ─────────────────────────────────────────────────────────────────
    backend_ = new SnifferBackend(this);
    model_   = new ConnectionModel(this);

    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model_);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1); // search all columns

    connect(search, &QLineEdit::textChanged,
            proxy_, &QSortFilterProxyModel::setFilterFixedString);

    table_ = new QTableView;
    table_->setModel(proxy_);
    table_->setObjectName("flowTable");
    table_->setSortingEnabled(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(false); // we colour-code manually
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    // Sensible column widths
    table_->setColumnWidth(0, 130); // Src IP
    table_->setColumnWidth(1,  60); // SPort
    table_->setColumnWidth(2, 130); // Dst IP
    table_->setColumnWidth(3,  60); // DPort
    table_->setColumnWidth(4,  55); // Proto
    table_->setColumnWidth(5,  80); // Packets
    table_->setColumnWidth(6,  90); // Bytes
    table_->setColumnWidth(7, 140); // Process

    vLayout->addWidget(table_);

    // Status bar
    statusBar()->setObjectName("statusBar");
    statusBar()->showMessage("Ready — waiting for packets…");
}

// ── Dark theme ────────────────────────────────────────────────────────────────
void MainWindow::applyDarkStyle() {
    qApp->setStyle("Fusion");

    QPalette p;
    p.setColor(QPalette::Window,          QColor(18,  18,  24));
    p.setColor(QPalette::WindowText,      QColor(220, 220, 230));
    p.setColor(QPalette::Base,            QColor(24,  24,  34));
    p.setColor(QPalette::AlternateBase,   QColor(30,  30,  42));
    p.setColor(QPalette::Text,            QColor(210, 210, 225));
    p.setColor(QPalette::Button,          QColor(35,  35,  50));
    p.setColor(QPalette::ButtonText,      QColor(210, 210, 225));
    p.setColor(QPalette::Highlight,       QColor(60,  100, 180));
    p.setColor(QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::ToolTipBase,     QColor(40, 40, 60));
    p.setColor(QPalette::ToolTipText,     Qt::white);
    qApp->setPalette(p);

    qApp->setStyleSheet(R"(
        QMainWindow { background: #12121a; }

        #headerFrame {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                         stop:0 #1a1a2e, stop:1 #16213e);
            border-radius: 6px;
            border: 1px solid #2a2a4a;
        }

        #titleLabel {
            font-size: 20px;
            font-weight: bold;
            color: #7eb8f7;
            letter-spacing: 1px;
        }

        #searchBox {
            background: #1e1e30;
            border: 1px solid #3a4a6a;
            border-radius: 4px;
            color: #c8d8f0;
            padding: 4px 8px;
            font-size: 12px;
        }
        #searchBox:focus {
            border: 1px solid #6090d0;
        }

        #statusLabel {
            color: #88a0c0;
            font-size: 11px;
        }

        #flowTable {
            background: #18182a;
            gridline-color: #2a2a3e;
            border: 1px solid #2a2a4a;
            border-radius: 4px;
            font-family: "Cascadia Code", "Consolas", monospace;
            font-size: 12px;
        }
        #flowTable::item:selected {
            background: rgba(60,100,180,0.45);
        }

        QHeaderView::section {
            background: #222236;
            color: #99b0d0;
            font-size: 11px;
            font-weight: bold;
            border: none;
            border-right: 1px solid #2a2a3e;
            border-bottom: 1px solid #3a3a5a;
            padding: 5px 6px;
        }
        QHeaderView::section:hover {
            background: #2a2a46;
        }

        QScrollBar:vertical {
            background: #1a1a2a;
            width: 8px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #3a4a6a;
            border-radius: 4px;
        }

        QStatusBar {
            background: #12121e;
            color: #6080a0;
            font-size: 11px;
        }
    )");
}

// ── Slots ─────────────────────────────────────────────────────────────────────

// Called every 1 000 ms by QTimer — runs on main thread, safe.
void MainWindow::onRefreshTimer() {
    auto snap = backend_->snapshot();
    model_->refresh(std::move(snap));

    uint64_t pkts  = backend_->totalPackets();
    uint64_t bytes = backend_->totalBytes();

    statusLbl_->setText(
        QString("Flows: %1   |   Pkts: %2   |   Bytes: %3")
            .arg(model_->rowCount())
            .arg(pkts)
            .arg(bytes)
    );
}

// Called from worker thread via Qt::QueuedConnection — runs on main thread.
void MainWindow::onNewConnection(QString srcIp, QString dstIp,
                                 quint16 srcPort, quint16 dstPort,
                                 QString protocol, QString process) {
    statusBar()->showMessage(
        QString("New: %1:%2 → %3:%4  [%5]  %6")
            .arg(srcIp).arg(srcPort)
            .arg(dstIp).arg(dstPort)
            .arg(protocol)
            .arg(process.isEmpty() ? "unknown" : process),
        4000 // clear after 4 s
    );
}

void MainWindow::onError(QString message) {
    QMessageBox::critical(this, "PacketLens — Error", message);
}
