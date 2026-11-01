"""
KillChain WebSocket Manager & Live Attack Graph Evolution Engine.
Handles real-time bi-directional streaming of attack graph updates, heartbeats,
sequence IDs, snapshot recovery, duplicate prevention, and bounded outbound queues.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect

from backend.graph.engine import AttackGraphEngine


class GraphWebSocketManager:
    """
    Manages live WebSocket subscriptions for the dynamic attack graph.
    Broadcasts incremental deltas, guarantees sequence ordering, and enforces bounded memory.
    """

    def __init__(self, max_history: int = 100):
        self.active_connections: Set[WebSocket] = set()
        self.sequence_id: int = 0
        self.max_history = max_history
        self.recent_deltas: deque = deque(maxlen=max_history)
        self.seen_event_ids: Set[str] = set()
        self._seen_queue: deque = deque(maxlen=2000)
        self.graph_engine = AttackGraphEngine()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send initial connection handshake with latest sequence ID
        await websocket.send_json({
            "type": "connected",
            "status": "ready",
            "sequence_id": self.sequence_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "connected_clients": len(self.active_connections),
        })

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    def is_duplicate(self, event_id: str) -> bool:
        """Check duplicate event ID and maintain bounded cache."""
        if not event_id:
            return False
        if event_id in self.seen_event_ids:
            return True
        if len(self._seen_queue) >= 2000:
            oldest = self._seen_queue.popleft()
            self.seen_event_ids.discard(oldest)
        self._seen_queue.append(event_id)
        self.seen_event_ids.add(event_id)
        return False

    async def broadcast_delta(self, delta: Dict[str, Any]) -> None:
        """Broadcast incremental graph updates to all active clients."""
        self.sequence_id += 1
        payload = {
            "type": "graph_delta",
            "sequence_id": self.sequence_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            **delta,
        }
        self.recent_deltas.append(payload)

        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast_threat_intercept(self, upload_id: str, threat: Dict[str, Any]) -> None:
        """Broadcast in-flight intercepted threat to connected SOC clients in real time."""
        self.sequence_id += 1
        payload = {
            "type": "in_flight_threat_intercept",
            "upload_id": upload_id,
            "sequence_id": self.sequence_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "threat": threat,
        }
        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

    async def send_heartbeat(self) -> None:
        """Periodic heartbeat ping to all connected clients."""
        payload = {
            "type": "heartbeat",
            "sequence_id": self.sequence_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "active_clients": len(self.active_connections),
        }
        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

    def process_live_event(self, event: Dict[str, Any], dataset_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Process single incoming live event:
        1. Duplicate prevention
        2. Normalize & entity resolution
        3. Incrementally update attack graph nodes and edges
        4. Recalculate reachability & asset risk
        """
        event_id = event.get("event_id") or event.get("event", {}).get("id") or f"live-{time.time_ns()}"
        if self.is_duplicate(event_id):
            return None

        delta = self.graph_engine.ingest_event_incremental(event, dataset_id=dataset_id)
        return delta


# Global singleton manager instance
ws_manager = GraphWebSocketManager()

