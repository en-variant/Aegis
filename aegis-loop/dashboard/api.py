import asyncio
import json
import queue
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis_loop import database, event_log
from aegis_loop import events as event_store
from aegis_loop.auth import current_user
from dashboard.applications_api import integration_router
from dashboard.applications_api import router as applications_router
from dashboard.auth_api import router as auth_router

ROOT = Path(__file__).resolve().parents[1]
CurrentUser = Annotated[dict[str, Any], Depends(current_user)]
WEB_ORIGINS = ["http://127.0.0.1:5173", "http://localhost:5173"]
APP_ORIGINS = {
    *WEB_ORIGINS,
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}

@asynccontextmanager
async def lifespan(_app: FastAPI):
    database.initialize()
    yield


app = FastAPI(
    title="Aegis Loop Local Security Service",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=WEB_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(auth_router)
app.include_router(applications_router)
app.include_router(integration_router)


@app.middleware("http")
async def enforce_local_browser_origin(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    origin = request.headers.get("origin")
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and origin is not None
        and origin not in APP_ORIGINS
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": "Untrusted browser origin"},
        )
    return await call_next(request)


@app.get("/api/health")
def health() -> dict[str, str]:
    with database.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}


def _owned_app_ids(user: dict[str, Any]) -> set[str]:
    return {
        str(application["id"])
        for application in database.list_apps(str(user["id"]))
    }


@app.get("/events")
def list_events(
    user: CurrentUser,
    since_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=5000),
) -> list[dict[str, Any]]:
    app_ids = _owned_app_ids(user)
    return [
        event_log.event_json(event)
        for event in event_log.read_events(since_seq=since_seq, limit=5000)
        if event_log.owner_visible(event, app_ids)
    ][:limit]


@app.get("/events/stream")
async def stream_events(
    user: CurrentUser,
    since_seq: int = Query(default=0, ge=0),
) -> StreamingResponse:
    app_ids = _owned_app_ids(user)

    async def stream():
        sequence = since_seq
        last_heartbeat = asyncio.get_running_loop().time()
        yield ": connected\n\n"
        while True:
            batch = event_log.read_events(since_seq=sequence, limit=500)
            for event in batch:
                sequence = event.seq
                if event_log.owner_visible(event, app_ids):
                    yield f"data: {json.dumps(event_log.event_json(event))}\n\n"
            now = asyncio.get_running_loop().time()
            if not batch and now - last_heartbeat >= 15:
                yield ": heartbeat\n\n"
                last_heartbeat = now
            await asyncio.sleep(0.25)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.websocket("/api/live")
async def live_events(websocket: WebSocket) -> None:
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in APP_ORIGINS:
        await websocket.close(code=1008)
        return
    session = websocket.cookies.get("aegis_session")
    if not session:
        await websocket.close(code=1008)
        return
    from aegis_loop.auth import _token_hash

    user = database.get_session_user(_token_hash(session))
    if user is None:
        await websocket.close(code=1008)
        return
    app_id = websocket.query_params.get("app_id")
    if not app_id or database.get_owned_app(str(user["id"]), app_id) is None:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    subscriber = event_store.subscribe()
    try:
        while True:
            try:
                message = await asyncio.to_thread(subscriber.get, True, 1)
            except queue.Empty:
                await websocket.send_json({"type": "heartbeat"})
                continue
            if (
                message.get("owner_id") != str(user["id"])
                or message.get("app_id") != app_id
            ):
                continue
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    finally:
        event_store.unsubscribe(subscriber)


WEB_DIST = ROOT / "web" / "dist"
if WEB_DIST.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="dashboard")
