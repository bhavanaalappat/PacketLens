#pragma once
#ifndef NETWORK_GRAPH_WIDGET_H
#define NETWORK_GRAPH_WIDGET_H

// network_graph_widget.h — v2
//
// Force-directed graph using a proper spring-embedder:
//
//  Repulsion:  Coulomb  F = Kr / d²        (all node pairs)
//  Attraction: Hooke    F = Ks * (d - L0)  (connected pairs only)
//  Centering:  Weak     F = Kc * dist_from_origin  (prevents drift)
//  Damping:    0.80× per tick
//
// Nodes are QGraphicsItems; the scene's advance() drives physics.
// Edges are QGraphicsLineItems redrawn every tick.

#include <QGraphicsView>
#include <QGraphicsScene>
#include <QMap>
#include <QTimer>
#include <QString>
#include <QPoint>
#include <cstdint>
#include "flow_manager.h"
#include "graph_node.h"

class QGraphicsLineItem;

struct GraphEdge {
    GraphNode*         source = nullptr;
    GraphNode*         remote = nullptr;
    QGraphicsLineItem* line   = nullptr;
};

struct HostSummary {
    QString ip;
    uint64_t bytes = 0;
    uint64_t packets = 0;
    uint64_t flows = 0;
};

class NetworkGraphWidget : public QGraphicsView {
    Q_OBJECT

public:
    explicit NetworkGraphWidget(QWidget* parent = nullptr);

    void updateFromSnapshot(const std::vector<FlowSnapshot>& snap);

signals:
    void nodeSelected(QString ip, uint64_t bytes, uint64_t packets,
                      QString process, quint16 port, QString state);
    void hostSelected(QString host, QString ip, uint64_t bytes,
                      uint64_t packets, uint64_t flows);

protected:
    void mousePressEvent(QMouseEvent*)  override;
    void mouseMoveEvent(QMouseEvent*)   override;
    void mouseReleaseEvent(QMouseEvent*) override;
    void wheelEvent(QWheelEvent*)       override;
    void resizeEvent(QResizeEvent*)     override;

private slots:
    void physicsStep();

private:
    GraphNode* spawnNode(GraphNode::NodeType type, const QString& label, const QPointF& pos);
    void       syncEdge(GraphEdge& edge);
    QPointF    randomOrbitPos(const QPointF& center) const;
    QPointF    hostOrbitPos(int index, int count) const;
    QRectF     activeGraphBounds() const;
    void       updateSceneBounds();
    void       fitToActiveGraph();
    QString    hostLabel(const FlowSnapshot& flow) const;

    QGraphicsScene* scene_  = nullptr;
    GraphNode*      master_ = nullptr;
    QMap<QString, GraphNode*> hostNodes_;
    QMap<QString, HostSummary> hostSummaries_;
    QMap<QString, GraphEdge> edges_;
    QMap<QString, QGraphicsLineItem*> hostLinks_;
    QTimer* physTimer_ = nullptr;
    int autoFitTicksRemaining_ = 0;
    double zoomFactor_ = 1.0;
    bool userControlledView_ = false;
    bool panning_ = false;
    QPoint panPressPos_;
    QPoint panLastPos_;
    GraphNode* pressedNode_ = nullptr;

    // Scene logical bounds
    static constexpr qreal W = 980.0;
    static constexpr qreal H = 680.0;

    // Physics tuning
    static constexpr double Kr = 9000.0;   // repulsion strength
    static constexpr double Ks = 0.052;    // spring constant
    static constexpr double L0 = 170.0;    // spring rest length
    static constexpr double Kc = 0.007;    // centering pull
    static constexpr double DAMP = 0.72;   // velocity damping per tick
    static constexpr double MAX_F = 14.0;  // force clamp (pixels/tick²)
    static constexpr int AUTO_FIT_TICKS_ON_NEW_NODE = 8;
    static constexpr double MIN_ZOOM = 0.25;
    static constexpr double MAX_ZOOM = 4.0;
};

#endif // NETWORK_GRAPH_WIDGET_H
