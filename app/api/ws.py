from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import jwt, JWTError

from app.config import settings
from app.security import ALGORITHM
from app.core.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/live")
async def live_feed(websocket: WebSocket, token: str = Query(...)):
    try:
        jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; client doesn't need to send anything.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)
