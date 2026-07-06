// side_panel.cpp
#include "side_panel.h"
#include "port_config.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QFont>
#include <QColor>
#include <QLocale>

static QString formatBytes(uint64_t b) {
    if (b < 1024)             return QString("%1 B").arg(b);
    if (b < 1024 * 1024)     return QString("%1 KB").arg(b / 1024.0, 0, 'f', 1);
    if (b < 1024*1024*1024)  return QString("%1 MB").arg(b / (1024.0*1024), 0, 'f', 2);
    return QString("%1 GB").arg(b / (1024.0*1024*1024), 0, 'f', 2);
}

// ── Helper: a labelled value row ─────────────────────────────────────────────
static void addRow(QVBoxLayout* layout, const QString& caption, QLabel*& valueOut) {
    auto* row = new QWidget;
    auto* rl  = new QHBoxLayout(row);
    rl->setContentsMargins(0, 2, 0, 2);
    rl->setSpacing(6);

    auto* capLbl = new QLabel(caption + ":");
    capLbl->setStyleSheet("color:#5a7a9a; font-size:10px; font-weight:bold;");
    capLbl->setFixedWidth(72);
    capLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

    valueOut = new QLabel("—");
    valueOut->setStyleSheet("color:#c8deff; font-size:12px;");
    valueOut->setWordWrap(true);

    rl->addWidget(capLbl);
    rl->addWidget(valueOut, 1);
    layout->addWidget(row);
}

// ── Constructor ───────────────────────────────────────────────────────────────
SidePanel::SidePanel(QWidget* parent) : QWidget(parent) {
    buildUi();
}

void SidePanel::buildUi() {
    setMinimumWidth(210);
    setMaximumWidth(240);
    setStyleSheet(R"(
        SidePanel {
            background: #10121d;
            border-left: 1px solid #26314a;
        }
    )");

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(10, 10, 10, 10);
    outer->setSpacing(8);

    // Header
    auto* header = new QLabel("Node Inspector");
    header->setStyleSheet(
        "color:#8fc5ff; font-size:13px; font-weight:bold; "
        "border-bottom:1px solid #26314a; padding-bottom:6px;");
    outer->addWidget(header);

    // Card
    card_ = new QFrame;
    card_->setObjectName("nodeCard");
    card_->setStyleSheet(R"(
        #nodeCard {
            background: #151a27;
            border: 1px solid #31405e;
            border-radius: 6px;
        }
    )");
    auto* cardLayout = new QVBoxLayout(card_);
    cardLayout->setContentsMargins(10, 10, 10, 10);
    cardLayout->setSpacing(3);

    // IP (large)
    ipLbl_ = new QLabel("—");
    ipLbl_->setStyleSheet(
        "color:#8fc5ff; font-size:14px; font-weight:bold; "
        "font-family:'Cascadia Code','Consolas',monospace;");
    ipLbl_->setAlignment(Qt::AlignCenter);
    cardLayout->addWidget(ipLbl_);

    // State badge
    stateLbl_ = new QLabel("—");
    stateLbl_->setAlignment(Qt::AlignCenter);
    stateLbl_->setStyleSheet(
        "background:#1e2a3a; color:#88b0d8; border-radius:4px; "
        "font-size:10px; padding:2px 6px;");
    cardLayout->addWidget(stateLbl_);
    cardLayout->addSpacing(8);

    addRow(cardLayout, "Port",    portLbl_);
    addRow(cardLayout, "Service", portCatLbl_);
    addRow(cardLayout, "Process", processLbl_);
    addRow(cardLayout, "Bytes",   bytesLbl_);
    addRow(cardLayout, "Packets", packetsLbl_);

    outer->addWidget(card_);

    // Placeholder shown when nothing selected
    placeholderLbl_ = new QLabel("Click a node\nin the graph\nto inspect it.");
    placeholderLbl_->setAlignment(Qt::AlignCenter);
    placeholderLbl_->setStyleSheet("color:#3a4a6a; font-size:11px; padding:20px;");
    outer->addWidget(placeholderLbl_);

    outer->addStretch();

    // Legend
    auto* legendTitle = new QLabel("Port Colors");
    legendTitle->setStyleSheet("color:#6f8db3; font-size:10px; font-weight:bold;");
    outer->addWidget(legendTitle);

    struct LegEntry { QString col; QString text; };
    for (auto [col, text] : QVector<LegEntry>{
            {"#3affb0", "Secure"},
            {"#ff3a3a", "Insecure"},
            {"#ffb03a", "Network Service"},
            {"#ffe033", "Unclassified"} })
    {
        auto* row = new QWidget;
        auto* rl  = new QHBoxLayout(row);
        rl->setContentsMargins(0, 1, 0, 1);
        rl->setSpacing(6);

        auto* dot = new QLabel("●");
        dot->setStyleSheet(QString("color:%1; font-size:14px;").arg(col));
        dot->setFixedWidth(16);

        auto* txt = new QLabel(text);
        txt->setStyleSheet("color:#6080a0; font-size:10px;");

        rl->addWidget(dot);
        rl->addWidget(txt, 1);
        outer->addWidget(row);
    }

    card_->setVisible(false);
}

// ── Public API ────────────────────────────────────────────────────────────────
void SidePanel::showNode(const QString& ip,
                          uint64_t bytes, uint64_t packets,
                          const QString& process, uint16_t port,
                          const QString& state)
{
    card_->setVisible(true);
    placeholderLbl_->setVisible(false);

    ipLbl_->setText(ip);

    // State badge colour
    QString stateCol = "#88b0d8";
    if (state == "EST")    stateCol = "#3affb0";
    if (state == "CLOSED") stateCol = "#ff3a3a";
    if (state == "NEW")    stateCol = "#ffb03a";
    stateLbl_->setText(state);
    stateLbl_->setStyleSheet(
        QString("background:#1e2a3a; color:%1; border-radius:4px; "
                "font-size:10px; padding:2px 6px;").arg(stateCol));

    portLbl_->setText(QString::number(port));

    PortRule rule = PortConfig::instance().classify(port);
    QColor catCol = PortConfig::colorFor(rule.category);
    portCatLbl_->setText(rule.label.isEmpty() ? "—" : rule.label);
    portCatLbl_->setStyleSheet(
        QString("color:%1; font-size:12px;").arg(catCol.name()));

    processLbl_->setText(process.isEmpty() ? "(unknown)" : process);
    bytesLbl_->setText(formatBytes(bytes));
    packetsLbl_->setText(QLocale().toString(static_cast<qlonglong>(packets)));
}

void SidePanel::showHost(const QString& host,
                         const QString& ip,
                         uint64_t bytes, uint64_t packets,
                         uint64_t flows)
{
    card_->setVisible(true);
    placeholderLbl_->setVisible(false);

    ipLbl_->setText(host);
    stateLbl_->setText("HOST");
    stateLbl_->setStyleSheet(
        "background:#1e2a3a; color:#8fc5ff; border-radius:4px; "
        "font-size:10px; padding:2px 6px;");

    portLbl_->setText(ip.isEmpty() ? "—" : ip);
    portCatLbl_->setText(QString("%1 flows").arg(
        QLocale().toString(static_cast<qlonglong>(flows))));
    portCatLbl_->setStyleSheet("color:#8fc5ff; font-size:12px;");
    processLbl_->setText("host summary");
    bytesLbl_->setText(formatBytes(bytes));
    packetsLbl_->setText(QLocale().toString(static_cast<qlonglong>(packets)));
}

void SidePanel::clear() {
    card_->setVisible(false);
    placeholderLbl_->setVisible(true);
}
