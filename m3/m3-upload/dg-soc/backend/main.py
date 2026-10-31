"""DeceptionGraph SOC backend. Loopback only."""
import json
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .db import Database
from .integrations import Integrations
from .models import IngestEvent, reason_for

HOST = "127.0.0.1"  # never bind anything else (AGENTS.md section 6)
PORT = 8000
MAX_BATCH = 100
MAX_BODY_BYTES = 1024 * 1024
LAB_NOTE = "Simulated lab data from DeceptionGraph SOC decoys. No real systems, people or credentials."


class Broadcaster:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def send(self, message: dict) -> None:
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                self.clients.discard(ws)


class LinkDecision(BaseModel):
    decision: Literal["confirm", "reject"]
    rationale: str = Field(min_length=5, max_length=1000)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def create_app(db_path: Optional[str] = None) -> FastAPI:
    db = Database(db_path)
    hub = Broadcaster()
    hooks = Integrations()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        db.close()

    app = FastAPI(title="DeceptionGraph SOC", version="1.0", lifespan=lifespan)
    app.state.db = db
    app.state.hooks = hooks

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 413: "too_large", 400: "bad_request"}.get(exc.status_code, "error")
        return _error(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        err = exc.errors()[0]
        loc = ".".join(str(p) for p in err["loc"] if p not in ("query", "body"))
        return _error(400, "bad_request", f"{loc}: {err['msg']}")

    def require_incident(incident_id: str) -> None:
        if not db.incident_exists(incident_id):
            raise HTTPException(404, f"incident {incident_id} not found")

    def full_incident(incident_id: str) -> dict:
        inc = db.incident_detail(incident_id)
        inc["summary"] = hooks.summary(inc)
        inc["active_block"] = hooks.active_block(inc["src_ip"])
        return inc

    async def publish(findings: list, links: list, incidents: list) -> None:
        seq = db.max_seq()
        for f in findings:
            await hub.send({"seq": seq, "type": "finding", "data": f})
        for l in links:
            await hub.send({"seq": seq, "type": "link", "data": db.public_link(l)})
        for inc_id in incidents:
            await hub.send({"seq": seq, "type": "incident", "data": db.incident_summary(inc_id)})

    # ---- ingest ----
    @app.post("/api/ingest/events")
    async def ingest(request: Request):
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(413, "body larger than 1 MiB")
        try:
            body = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "body is not valid JSON")
        items = body.get("events") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise HTTPException(400, 'body must be {"events": [...]}')
        if len(items) > MAX_BATCH:
            raise HTTPException(413, f"more than {MAX_BATCH} events in one request")

        valid: list[IngestEvent] = []
        rejected: list[dict] = []
        for i, item in enumerate(items):
            try:
                valid.append(IngestEvent.model_validate(item))
            except ValidationError as e:
                rejected.append({"index": i, "reason": reason_for(e)})

        result = db.ingest(valid)  # commit happens inside; everything below runs after it
        accepted = [s for s in result["stored"] if s is not None]
        for ev in accepted:
            await hub.send({"seq": ev["seq"], "type": "event", "data": ev})
        await publish(result["findings"], result["links"], result["incidents"])
        for ev in accepted:
            await hooks.on_event(ev)
        return {"accepted": len(accepted), "duplicates": len(result["stored"]) - len(accepted),
                "rejected": rejected}

    # ---- reads ----
    @app.get("/api/events")
    def events(incident_id: Optional[str] = None, sensor_id: Optional[str] = None,
               since_seq: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)):
        return db.list_events(incident_id, sensor_id, since_seq, limit)

    @app.get("/api/incidents")
    def incidents():
        return {"items": db.list_incidents()}

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str):
        require_incident(incident_id)
        return full_incident(incident_id)

    @app.get("/api/incidents/{incident_id}/transcript")
    def transcript(incident_id: str, session_id: Optional[str] = Query(None, max_length=128)):
        require_incident(incident_id)
        out = db.transcript(incident_id, session_id)
        if out is None:
            raise HTTPException(404, f"session {session_id} not found in {incident_id}")
        return out

    @app.get("/api/incidents/{incident_id}/export")
    def export(incident_id: str):
        require_incident(incident_id)
        body = full_incident(incident_id)
        body["events"] = db.export_events(incident_id)
        body["note"] = LAB_NOTE
        return JSONResponse(body, headers={
            "Content-Disposition": f'attachment; filename="{incident_id}.json"'})

    @app.get("/api/links")
    def links():
        return {"items": db.list_links()}

    @app.post("/api/links/{link_id}/decision")
    async def decide(link_id: str, body: LinkDecision):
        result = db.decide_link(link_id, body.decision, body.rationale.strip())
        if result is None:
            raise HTTPException(404, f"link {link_id} not found")
        link = db.public_link(result["link"])
        await hub.send({"seq": db.max_seq(), "type": "link", "data": link})
        await publish(result["findings"], [], result["incidents"])
        return link

    @app.get("/api/stats/overview")
    def stats():
        return db.stats()

    @app.get("/api/health")
    def health():
        return {"ok": True, "sensors": db.sensor_last_seen()}

    @app.websocket("/ws/events")
    async def ws_events(ws: WebSocket):
        await ws.accept()
        hub.clients.add(ws)
        try:
            while True:
                await ws.receive_text()  # server-push only; ignore client chatter
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(ws)

    hooks.mount(app)
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=HOST, port=PORT)
