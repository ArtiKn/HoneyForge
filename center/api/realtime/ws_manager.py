import asyncio

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self._listener_available = False
        self._state_lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        async with self._state_lock:
            if not self._listener_available:
                await websocket.close(code=1013)
                return False
            await websocket.accept()
            self.active_connections.add(websocket)
            return True

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def listener_started(self) -> None:
        async with self._state_lock:
            self._listener_available = True

    async def listener_stopped(self) -> None:
        async with self._state_lock:
            self._listener_available = False
            connections = tuple(self.active_connections)
            self.active_connections.clear()
        await asyncio.gather(
            *(connection.close(code=1012) for connection in connections),
            return_exceptions=True,
        )

    async def broadcast(self, message: dict[str, object]) -> None:
        stale: list[WebSocket] = []
        for connection in tuple(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)

