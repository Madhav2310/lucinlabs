"""WebSocket Real-Time Scoring Stream.

Provides a WebSocket endpoint that streams anomaly scores as they're
computed. Clients (dashboards, monitoring UIs) connect once and receive
a continuous feed of:

- Agent actions as they're scored
- Anomaly alerts in real-time
- Drift detection events
- Baseline progress updates

Protocol:
    Client connects to: ws://host:port/ws/stream
    Server pushes JSON messages:
    {
        "type": "score",        // score | alert | drift | baseline_progress
        "agent_id": "...",
        "tool": "...",
        "score": 42,
        "action": "allow",
        "factors": [...],
        "timestamp": "..."
    }

This is essential for any real-time dashboard or SOC integration.
Without WebSocket, clients must poll — which adds latency and load.
"""

import json
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect


class ConnectionManager:
    """Manages WebSocket connections for real-time streaming."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send a message to ALL connected clients."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except (WebSocketDisconnect, RuntimeError):
                dead_connections.append(connection)

        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

    async def send_to(self, websocket: WebSocket, message: dict):
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except (WebSocketDisconnect, RuntimeError):
            self.disconnect(websocket)

    @property
    def client_count(self) -> int:
        """Number of active connections."""
        return len(self.active_connections)


# Global connection manager
manager = ConnectionManager()


async def emit_score_event(
    agent_id: str,
    tool: str,
    score: int,
    action: str,
    factors: list[str],
):
    """Emit a scoring event to all connected WebSocket clients.

    Call this from the scoring pipeline whenever an action is scored.
    """
    event = {
        "type": "score",
        "agent_id": agent_id,
        "tool": tool,
        "score": score,
        "action": action,
        "factors": factors,
        "timestamp": datetime.now().isoformat(),
    }
    await manager.broadcast(event)


async def emit_alert_event(
    agent_id: str,
    tool: str,
    score: int,
    factors: list[str],
    severity: str = "high",
):
    """Emit an alert event (score exceeded threshold)."""
    event = {
        "type": "alert",
        "agent_id": agent_id,
        "tool": tool,
        "score": score,
        "severity": severity,
        "factors": factors,
        "timestamp": datetime.now().isoformat(),
    }
    await manager.broadcast(event)


async def emit_drift_event(agent_id: str, magnitude: float, recommendation: str):
    """Emit a concept drift detection event."""
    event = {
        "type": "drift",
        "agent_id": agent_id,
        "magnitude": magnitude,
        "recommendation": recommendation,
        "timestamp": datetime.now().isoformat(),
    }
    await manager.broadcast(event)


async def emit_baseline_progress(agent_id: str, progress_pct: int):
    """Emit baseline learning progress update."""
    event = {
        "type": "baseline_progress",
        "agent_id": agent_id,
        "progress_pct": progress_pct,
        "timestamp": datetime.now().isoformat(),
    }
    await manager.broadcast(event)


def register_websocket_routes(app):
    """Register WebSocket endpoints on a FastAPI app.

    Call this during app initialization:
        from lucin.integrations.websocket import register_websocket_routes
        register_websocket_routes(app)
    """

    @app.websocket("/ws/stream")
    async def websocket_stream(websocket: WebSocket):
        """Main streaming endpoint. Clients receive all events."""
        await manager.connect(websocket)
        try:
            # Keep connection alive, handle client messages
            while True:
                # Wait for client messages (pings, subscription filters)
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    # Handle subscription filters
                    if msg.get("type") == "ping":
                        await manager.send_to(websocket, {"type": "pong"})
                    elif msg.get("type") == "subscribe":
                        # Future: filter events by agent_id
                        await manager.send_to(websocket, {
                            "type": "subscribed",
                            "filter": msg.get("agent_id", "*"),
                        })
                except json.JSONDecodeError:
                    pass
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    @app.websocket("/ws/health")
    async def websocket_health(websocket: WebSocket):
        """Health check WebSocket — returns connection count."""
        await websocket.accept()
        await websocket.send_json({
            "type": "health",
            "active_connections": manager.client_count,
            "timestamp": datetime.now().isoformat(),
        })
        await websocket.close()
