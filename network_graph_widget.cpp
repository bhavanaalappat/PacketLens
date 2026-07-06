// network_graph_widget.cpp — v2
#include "network_graph_widget.h"
#include "graph_node.h"
#include "port_config.h"

#include <QGraphicsScene>
#include <QGraphicsLineItem>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QResizeEvent>
#include <QTimer>
#include <QPen>
#include <QColor>
#include <QScrollBar>
#include <QRandomGenerator>
#include <QApplication>
#include <QVector>
#include <QSet>
#include <QtMath>
#include <algorithm>
#include <cmath>

namespace {
bool isKnownPort(uint16_t port) {
    return PortConfig::instance().classify(port).category != PortCategory::Unknown;
}

bool isEphemeralPort(uint16_t port) {
    return port >= 49152;
}

struct ServiceEndpoint {
    QString ip;
    uint16_t port = 0;
};

ServiceEndpoint chooseServiceEndpoint(const FlowSnapshot& flow) {
    QString srcIp = QString::fromStdString(flow.src_ip);
    QString dstIp = QString::fromStdString(flow.dst_ip);

    bool srcKnown = isKnownPort(flow.src_port);
    bool dstKnown = isKnownPort(flow.dst_port);

    if (dstKnown && !srcKnown) return { dstIp, flow.dst_port };
    if (srcKnown && !dstKnown) return { srcIp, flow.src_port };

    if (isEphemeralPort(flow.dst_port) && !isEphemeralPort(flow.src_port)) {
        return { srcIp, flow.src_port };
    }
    if (isEphemeralPort(flow.src_port) && !isEphemeralPort(flow.dst_port)) {
        return { dstIp, flow.dst_port };
    }

    if (flow.dst_port != 0) return { dstIp, flow.dst_port };
    return { dstIp.isEmpty() ? srcIp : dstIp, flow.src_port };
}
}

// ── Constructor ───────────────────────────────────────────────────────────────
NetworkGraphWidget::NetworkGraphWidget(QWidget* parent)
    : QGraphicsView(parent)
{
    scene_ = new QGraphicsScene(this);
    scene_->setSceneRect(-W/2, -H/2, W, H);
    setScene(scene_);

    setRenderHints(QPainter::Antialiasing | QPainter::TextAntialiasing |
                   QPainter::SmoothPixmapTransform);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(AnchorUnderMouse);
    setResizeAnchor(AnchorViewCenter);
    setBackgroundBrush(QColor(8, 10, 18));
    setFrameShape(QFrame::NoFrame);
    setOptimizationFlag(DontAdjustForAntialiasing, false);
    setViewportUpdateMode(QGraphicsView::BoundingRectViewportUpdate);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setCursor(Qt::OpenHandCursor);

    // Subtle range rings help depth without overpowering the graph.
    QPen ringPen(QColor(120, 150, 190, 16), 0.8, Qt::SolidLine);
    for (int r = 90; r <= 360; r += 90) {
        auto* ring = scene_->addEllipse(-r, -r, 2*r, 2*r, ringPen, Qt::NoBrush);
        ring->setZValue(-10);
    }

    QPen crossPen(QColor(120, 150, 190, 10), 0.6, Qt::DashLine);
    scene_->addLine(-W/2, 0, W/2, 0, crossPen)->setZValue(-10);
    scene_->addLine(0, -H/2, 0, H/2, crossPen)->setZValue(-10);

    // ── Physics at 25 fps ─────────────────────────────────────────────────────
    physTimer_ = new QTimer(this);
    connect(physTimer_, &QTimer::timeout, this, &NetworkGraphWidget::physicsStep);
    physTimer_->start(40);
}

// ── Snapshot update ───────────────────────────────────────────────────────────
void NetworkGraphWidget::updateFromSnapshot(const std::vector<FlowSnapshot>& snap) {
    // Aggregate by reporting host + destination IP + destination port.
    struct AggRow {
        uint64_t packets = 0, bytes = 0, bestScore = 0;
        QString  host, dstIp, process, state;
        uint16_t port = 0;
    };

    QMap<QString, AggRow> agg;
    QSet<QString> activeHosts;
    hostSummaries_.clear();
    for (const auto& s : snap) {
        QString host = hostLabel(s);
        ServiceEndpoint endpoint = chooseServiceEndpoint(s);
        QString key = QString("%1|%2|%3").arg(host, endpoint.ip).arg(endpoint.port);

        activeHosts.insert(host);
        HostSummary& summary = hostSummaries_[host];
        summary.bytes += s.bytes;
        summary.packets += s.packets;
        summary.flows += 1;
        if (summary.ip.isEmpty()) {
            QString src = QString::fromStdString(s.src_ip);
            QString dst = QString::fromStdString(s.dst_ip);
            summary.ip = endpoint.ip == src ? dst : src;
        }

        auto& a     = agg[key];
        a.host      = host;
        a.dstIp     = endpoint.ip;
        a.packets  += s.packets;
        a.bytes    += s.bytes;
        uint64_t score = s.bytes > 0 ? s.bytes : s.packets;
        if (score >= a.bestScore) {
            a.bestScore = score;
            a.port      = endpoint.port;
            a.state     = QString::fromStdString(s.state);
        }
        if (!s.process.empty()) {
            a.process = QString::fromStdString(s.process);
        }
    }

    int hostIndex = 0;
    int hostCount = std::max(1, static_cast<int>(activeHosts.size()));
    for (const QString& host : activeHosts) {
        if (!hostNodes_.contains(host)) {
            QPointF pos = hostCount == 1 ? QPointF(0, 0) : hostOrbitPos(hostIndex, hostCount);
            GraphNode* node = spawnNode(GraphNode::Master, host, pos);
            hostNodes_[host] = node;
            if (!master_) master_ = node;
            autoFitTicksRemaining_ = AUTO_FIT_TICKS_ON_NEW_NODE;
        }

        QPointF target = hostCount == 1 ? QPointF(0, 0) : hostOrbitPos(hostIndex, hostCount);
        hostNodes_[host]->setPos(target);
        ++hostIndex;
    }

    for (auto it = hostNodes_.begin(); it != hostNodes_.end(); ) {
        if (!activeHosts.contains(it.key())) {
            GraphNode* node = it.value();
            scene_->removeItem(node);
            delete node;
            it = hostNodes_.erase(it);
        } else {
            ++it;
        }
    }
    master_ = hostNodes_.isEmpty() ? nullptr : hostNodes_.begin().value();

    QSet<QString> desiredHostLinks;
    if (activeHosts.size() > 1 && hostNodes_.contains("local")) {
        GraphNode* local = hostNodes_["local"];
        for (const QString& host : activeHosts) {
            if (host == "local") continue;
            QString linkKey = QString("local|%1").arg(host);
            desiredHostLinks.insert(linkKey);
            if (!hostLinks_.contains(linkKey)) {
                auto* line = scene_->addLine(0, 0, 0, 0);
                line->setZValue(0);
                hostLinks_[linkKey] = line;
            }
            GraphNode* other = hostNodes_.value(host, nullptr);
            if (other) {
                QLineF link(local->pos(), other->pos());
                hostLinks_[linkKey]->setLine(link);
                hostLinks_[linkKey]->setPen(QPen(QColor(126, 184, 247, 120), 1.4,
                                                 Qt::DashLine, Qt::RoundCap));
            }
        }
    }

    for (auto it = hostLinks_.begin(); it != hostLinks_.end(); ) {
        if (!desiredHostLinks.contains(it.key())) {
            scene_->removeItem(it.value());
            delete it.value();
            it = hostLinks_.erase(it);
        } else {
            ++it;
        }
    }

    // Add new destination nodes / update existing.
    for (auto it = agg.begin(); it != agg.end(); ++it) {
        const QString& edgeKey = it.key();
        const AggRow&  row = it.value();
        GraphNode* source = hostNodes_.value(row.host, nullptr);
        if (!source) continue;

        if (!edges_.contains(edgeKey)) {
            GraphNode* node = spawnNode(GraphNode::Remote, row.dstIp, randomOrbitPos(source->pos()));
            QGraphicsLineItem* line = scene_->addLine(source->pos().x(), source->pos().y(),
                                                      node->pos().x(), node->pos().y());
            line->setZValue(1);
            edges_[edgeKey] = { source, node, line };
            autoFitTicksRemaining_ = AUTO_FIT_TICKS_ON_NEW_NODE;
        }

        GraphEdge& edge = edges_[edgeKey];
        edge.source = source;
        edge.remote->setFlowData(row.packets, row.bytes, row.process, row.port, row.state);
        syncEdge(edge);
    }

    // Remove destination nodes that are no longer visible in the current host filter.
    for (auto it = edges_.begin(); it != edges_.end(); ) {
        if (!agg.contains(it.key())) {
            scene_->removeItem(it.value().line);
            scene_->removeItem(it.value().remote);
            delete it.value().line;
            delete it.value().remote;
            it = edges_.erase(it);
        } else {
            ++it;
        }
    }

    updateSceneBounds();
}

// ── Spawn ─────────────────────────────────────────────────────────────────────
GraphNode* NetworkGraphWidget::spawnNode(GraphNode::NodeType type, const QString& label, const QPointF& pos) {
    auto* node = new GraphNode(type, label);
    node->setPos(pos);
    // Give it a small random kick so nodes immediately start separating
    node->vel_ = QPointF(
        (QRandomGenerator::global()->bounded(20) - 10),
        (QRandomGenerator::global()->bounded(20) - 10));
    scene_->addItem(node);
    return node;
}

QPointF NetworkGraphWidget::randomOrbitPos(const QPointF& center) const {
    auto* rng  = QRandomGenerator::global();
    double ang = rng->bounded(360) * M_PI / 180.0;
    double r   = 120.0 + rng->bounded(80);
    return center + QPointF(r * std::cos(ang), r * std::sin(ang));
}

QPointF NetworkGraphWidget::hostOrbitPos(int index, int count) const {
    if (count <= 1) return QPointF(0, 0);
    double ang = (2.0 * M_PI * index / count) - (M_PI / 2.0);
    double r = 230.0;
    return QPointF(r * std::cos(ang), r * std::sin(ang));
}

// ── Edge sync ─────────────────────────────────────────────────────────────────
void NetworkGraphWidget::syncEdge(GraphEdge& edge) {
    if (!edge.remote || !edge.line) return;

    QPointF sp = edge.source ? edge.source->pos() : QPointF(0, 0);
    QPointF rp = edge.remote->pos();
    edge.line->setLine(sp.x(), sp.y(), rp.x(), rp.y());

    QColor col = edge.remote->edgeColor();
    float  w   = edge.remote->edgeWidth();

    bool closed = (edge.remote->state() == "CLOSED");
    col.setAlpha(closed ? 36 : 210);

    Qt::PenStyle style = closed ? Qt::DotLine : Qt::SolidLine;
    edge.line->setPen(QPen(col, w, style, Qt::RoundCap));
}

// ── Force-directed physics ────────────────────────────────────────────────────
//
// Per tick, for every non-pinned remote node n:
//
//  Force = Σ repulsion(n, all others)        [push apart]
//        + spring(n, master)                 [pull toward center]
//        + centering(n)                      [weak drift correction]
//
// velocity += force; velocity *= DAMP; position += velocity
//
// All forces clamped to MAX_F to prevent explosion on first frame.

void NetworkGraphWidget::physicsStep() {
    // Gather all remote nodes
    QVector<GraphNode*> nodes;
    nodes.reserve(edges_.size());
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        GraphNode* n = it.value().remote;
        if (n) nodes.append(n);
    }

    for (GraphNode* n : nodes) {
        if (n->pinned_) continue;

        QPointF pos  = n->pos();
        QPointF force(0, 0);
        QPointF anchor(0, 0);
        for (auto it = edges_.begin(); it != edges_.end(); ++it) {
            if (it.value().remote == n && it.value().source) {
                anchor = it.value().source->pos();
                break;
            }
        }

        // ── Repulsion: every node repels every other node ─────────────────────
        // Including host anchors.
        auto applyRepulsion = [&](QPointF other) {
            QPointF d    = pos - other;
            double dist2 = d.x()*d.x() + d.y()*d.y();
            if (dist2 < 1.0) { d = QPointF(1,1); dist2 = 2.0; }
            double dist  = std::sqrt(dist2);
            double f     = Kr / dist2;
            force += QPointF(d.x()/dist * f, d.y()/dist * f);
        };

        for (auto it = hostNodes_.begin(); it != hostNodes_.end(); ++it) {
            applyRepulsion(it.value()->pos());
        }
        for (GraphNode* other : nodes) {
            if (other == n) continue;
            applyRepulsion(other->pos());
        }

        // ── Spring: attraction toward the reporting host ──────────────────────
        {
            QPointF d    = anchor - pos;
            double  dist = std::sqrt(d.x()*d.x() + d.y()*d.y());
            if (dist > 0.5) {
                double stretch = dist - L0;           // positive → too far
                double f       = Ks * stretch;
                force += QPointF(d.x()/dist * f, d.y()/dist * f);
            }
        }

        // ── Centering: weak pull toward scene centre (prevents runaway drift) ─
        {
            force += QPointF(-Kc * pos.x(), -Kc * pos.y());
        }

        // ── Clamp force ───────────────────────────────────────────────────────
        double fmag = std::sqrt(force.x()*force.x() + force.y()*force.y());
        if (fmag > MAX_F)
            force *= MAX_F / fmag;

        n->vel_ += force;
        n->vel_ *= DAMP;
    }

    // Integrate positions
    scene_->advance();

    // Redraw edges
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        syncEdge(it.value());
    }
    for (auto it = hostLinks_.begin(); it != hostLinks_.end(); ++it) {
        const QStringList parts = it.key().split('|');
        if (parts.size() != 2) continue;
        GraphNode* a = hostNodes_.value(parts[0], nullptr);
        GraphNode* b = hostNodes_.value(parts[1], nullptr);
        if (a && b) it.value()->setLine(QLineF(a->pos(), b->pos()));
    }

    updateSceneBounds();

    if (autoFitTicksRemaining_ > 0) {
        if (!userControlledView_) fitToActiveGraph();
        --autoFitTicksRemaining_;
    }
}

QRectF NetworkGraphWidget::activeGraphBounds() const {
    QRectF bounds(-80, -80, 160, 160);
    for (auto it = edges_.begin(); it != edges_.end(); ++it) {
        if (it.value().remote) {
            bounds = bounds.united(it.value().remote->sceneBoundingRect());
        }
    }
    for (auto it = hostNodes_.begin(); it != hostNodes_.end(); ++it) {
        bounds = bounds.united(it.value()->sceneBoundingRect());
    }
    return bounds.adjusted(-220, -220, 220, 220);
}

void NetworkGraphWidget::updateSceneBounds() {
    QRectF bounds = activeGraphBounds();
    bounds = bounds.united(QRectF(-W / 2, -H / 2, W, H));
    scene_->setSceneRect(bounds);
}

void NetworkGraphWidget::fitToActiveGraph() {
    QRectF bounds = activeGraphBounds();
    fitInView(bounds, Qt::KeepAspectRatio);
    zoomFactor_ = 1.0;
}

// ── Mouse: click on node → emit signal + forward to item for pinning ──────────
void NetworkGraphWidget::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        QPointF sp   = mapToScene(event->pos());
        auto*   item = scene_->itemAt(sp, transform());
        pressedNode_ = dynamic_cast<GraphNode*>(item);
        panning_ = true;
        userControlledView_ = true;
        panPressPos_ = event->pos();
        panLastPos_ = event->pos();
        setCursor(Qt::ClosedHandCursor);
        event->accept();
        return;
    }
    QGraphicsView::mousePressEvent(event);
}

void NetworkGraphWidget::mouseMoveEvent(QMouseEvent* event) {
    if (panning_) {
        QPoint delta = event->pos() - panLastPos_;
        horizontalScrollBar()->setValue(horizontalScrollBar()->value() - delta.x());
        verticalScrollBar()->setValue(verticalScrollBar()->value() - delta.y());
        panLastPos_ = event->pos();
        event->accept();
        return;
    }
    QGraphicsView::mouseMoveEvent(event);
}

void NetworkGraphWidget::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && panning_) {
        bool wasClick = (event->pos() - panPressPos_).manhattanLength() < 5;
        if (wasClick && pressedNode_) {
            if (pressedNode_->isMaster()) {
                QString host = pressedNode_->ip();
                HostSummary summary = hostSummaries_.value(host);
                emit hostSelected(host, summary.ip, summary.bytes,
                                  summary.packets, summary.flows);
            } else {
                emit nodeSelected(
                    pressedNode_->ip(), pressedNode_->bytes(), pressedNode_->packets(),
                    pressedNode_->process(), pressedNode_->dstPort(), pressedNode_->state());
            }
        }
        pressedNode_ = nullptr;
        panning_ = false;
        setCursor(Qt::OpenHandCursor);
        event->accept();
        return;
    }
    QGraphicsView::mouseReleaseEvent(event);
}

void NetworkGraphWidget::wheelEvent(QWheelEvent* event) {
    if (event->modifiers() & Qt::ShiftModifier) {
        horizontalScrollBar()->setValue(
            horizontalScrollBar()->value() - event->angleDelta().y());
        event->accept();
        return;
    }

    if (event->angleDelta().y() != 0) {
        double f = event->angleDelta().y() > 0 ? 1.12 : (1.0 / 1.12);
        double nextZoom = std::clamp(zoomFactor_ * f, MIN_ZOOM, MAX_ZOOM);
        f = nextZoom / zoomFactor_;
        if (std::abs(f - 1.0) > 0.001) {
            zoomFactor_ = nextZoom;
            userControlledView_ = true;
            scale(f, f);
        }
        event->accept();
    } else {
        QGraphicsView::wheelEvent(event);
    }
}

void NetworkGraphWidget::resizeEvent(QResizeEvent* e) {
    QGraphicsView::resizeEvent(e);
    autoFitTicksRemaining_ = std::max(autoFitTicksRemaining_, 1);
}

QString NetworkGraphWidget::hostLabel(const FlowSnapshot& flow) const {
    return QString::fromStdString(flow.host.empty() ? "local" : flow.host);
}
