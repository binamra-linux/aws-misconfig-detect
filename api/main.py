"""
FastAPI wrapper around the detection backend. No detection logic lives here --
this adapts backend/ into a JSON API (plus an SSE progress stream) for the React
frontend, and serves the built SPA in production.

Auth is a signed, httpOnly session cookie rather than a bearer token. That's not
a stylistic choice: the browser's EventSource API cannot set request headers, so
an Authorization header is impossible on /api/scan/stream. A cookie is sent
automatically on both fetch() and EventSource, so it's the only scheme that
covers the whole API.

Run SINGLE-WORKER. Scan state lives in backend.scan_service's module globals, and
the scheduler is started per-process -- N workers would mean N inconsistent copies
of the current scan and N duplicate nightly scans/alert emails.
"""

import json
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from backend import config, history, scan_service, scheduler, users
from backend.ai.groq_client import explain_finding
from backend.models import CheckResult
from backend.remediation import get_remediation
from backend.scanner import build_session, enabled_regions, plan_stages, run_full_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title="CloudSentinel API", lifespan=lifespan)

# The secret must survive restarts or every session is invalidated on reload. We
# fall back to a random one so the app still *runs* unconfigured (dev/first boot),
# but that logs everyone out on restart -- hence the warning.
_session_secret = config.SESSION_SECRET
if not _session_secret:
    _session_secret = secrets.token_hex(32)
    logger.warning(
        "SESSION_SECRET is not set -- using a random one. Sessions will not survive a restart. "
        "Set SESSION_SECRET in .env for anything beyond local development."
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    max_age=config.SESSION_MAX_AGE,
    same_site="lax",
    # Must be False over plain-HTTP localhost: browsers drop Secure cookies on
    # http://, which shows up as "login succeeds, then instantly logged out".
    https_only=config.SESSION_HTTPS_ONLY,
)


# --- auth ---

def require_user(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return user


class Credentials(BaseModel):
    username: str
    password: str


@app.get("/api/auth/status")
def auth_status(request: Request) -> dict:
    """Unauthenticated on purpose -- the login screen needs to know whether this is
    a first run (no users yet -> show 'create admin account') before anyone can log in."""
    return {
        "needs_setup": users.user_count() == 0,
        "user": request.session.get("user"),
    }


@app.post("/api/auth/register")
def register(body: Credentials, request: Request) -> dict:
    # First-run bootstrap only. Once an account exists this closes permanently,
    # otherwise anyone reaching the port could grant themselves access.
    if users.user_count() > 0:
        raise HTTPException(status_code=403, detail="Registration is closed -- an account already exists.")

    try:
        users.create_user(body.username, body.password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    request.session["user"] = body.username.strip()
    return {"user": body.username.strip()}


@app.post("/api/auth/login")
def login(body: Credentials, request: Request) -> dict:
    username = users.verify_user(body.username, body.password)
    if username is None:
        raise HTTPException(status_code=401, detail="Incorrect username or password.")

    request.session["user"] = username
    return {"user": username}


@app.post("/api/auth/logout")
def logout(request: Request) -> dict:
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def me(user: str = Depends(require_user)) -> dict:
    return {"user": user}


# --- scanning ---

def _sse(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data)}\n\n"


@app.post("/api/scan")
def scan(user: str = Depends(require_user)) -> dict:
    """Non-streaming scan. Kept for scripting and non-browser callers; the web UI
    uses /api/scan/stream so it can show real progress."""
    if not scan_service.try_begin_scan("manual"):
        raise HTTPException(status_code=409, detail=scan_service.busy_message())

    try:
        checks = run_full_scan()
    except (ClientError, NoCredentialsError, ProfileNotFound) as e:
        raise HTTPException(status_code=502, detail=f"AWS scan failed: {e}")
    finally:
        scan_service.end_scan()

    response, _ = scan_service.finalize_scan(checks)
    return response


@app.get("/api/scan/stream")
def scan_stream(user: str = Depends(require_user)) -> StreamingResponse:
    """Streams one `progress` event per detector-stage, then a final `complete`.

    The stage list is computed per-scan (it depends on how many regions are
    configured) and sent up-front in a `start` event, so the client renders its
    progress bar from real work rather than a hardcoded guess.
    """
    if not scan_service.try_begin_scan("manual"):
        raise HTTPException(status_code=409, detail=scan_service.busy_message())

    def generate():
        try:
            stages = plan_stages()
            yield _sse("start", {"stages": [{"key": s.key, "label": s.label} for s in stages]})

            checks: List[CheckResult] = []
            for stage in stages:
                checks.extend(stage.run(build_session(stage.region)))
                yield _sse("progress", {"stage": stage.key, "label": stage.label, "done": True})

            response, _ = scan_service.finalize_scan(checks)
            yield _sse("complete", response)
        except (ClientError, NoCredentialsError, ProfileNotFound) as e:
            # Named "scan_error", not "error": EventSource reserves the "error"
            # event type for connection failures, so a server-sent "error" event
            # would be indistinguishable from a dropped connection.
            yield _sse("scan_error", {"detail": f"AWS scan failed: {e}"})
        finally:
            scan_service.end_scan()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.post("/api/reset")
def reset(user: str = Depends(require_user)) -> dict:
    if scan_service.scan_owner() is not None:
        raise HTTPException(status_code=409, detail="Can't reset while a scan is in progress.")

    scan_service.reset()
    return scan_service.findings_response()


@app.get("/api/findings")
def get_findings(user: str = Depends(require_user)) -> dict:
    return scan_service.findings_response()


@app.get("/api/resources")
def get_resources(user: str = Depends(require_user)) -> dict:
    return scan_service.resources_response()


@app.get("/api/history")
def get_history(user: str = Depends(require_user)) -> dict:
    return {"scans": history.load_history()}


# --- config ---

@app.get("/api/config")
def get_config(user: str = Depends(require_user)) -> dict:
    return {
        "aws_region": config.AWS_REGION,
        "aws_regions": config.AWS_REGIONS or config.AWS_REGION,
        "aws_profile": config.AWS_PROFILE or "default credential chain",
        "groq_model": config.GROQ_MODEL,
        "iam_unused_key_days": config.IAM_UNUSED_KEY_DAYS,
        "remediation_enabled": config.REMEDIATION_ENABLED,
        "schedule": scheduler.status(),
    }


class ConfigUpdate(BaseModel):
    iam_unused_key_days: int


@app.post("/api/config")
def update_config(body: ConfigUpdate, user: str = Depends(require_user)) -> dict:
    if body.iam_unused_key_days < 0:
        raise HTTPException(status_code=422, detail="iam_unused_key_days must be >= 0")
    # In-memory only -- not persisted to .env, resets on server restart.
    config.IAM_UNUSED_KEY_DAYS = body.iam_unused_key_days
    return get_config(user)


@app.get("/api/regions")
def get_regions(user: str = Depends(require_user)) -> dict:
    try:
        return {"regions": enabled_regions()}
    except (ClientError, NoCredentialsError, ProfileNotFound) as e:
        raise HTTPException(status_code=502, detail=f"Could not list regions: {e}")


# --- per-finding actions ---

def _lookup_finding(scan_id: int, finding_id: int):
    finding, error = scan_service.finding_at(scan_id, finding_id)
    if error == "stale":
        raise HTTPException(status_code=409, detail="This finding is from a stale scan -- re-fetch findings.")
    if error == "not_found":
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


@app.post("/api/findings/{scan_id}/{finding_id}/explain")
def explain(scan_id: int, finding_id: int, user: str = Depends(require_user)) -> dict:
    finding = _lookup_finding(scan_id, finding_id)

    try:
        explanation = explain_finding(finding)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"explanation": explanation}


@app.get("/api/findings/{scan_id}/{finding_id}/remediation")
def get_remediation_info(scan_id: int, finding_id: int, user: str = Depends(require_user)) -> dict:
    """What (if anything) this tool can fix automatically, and the exact AWS call it
    would make. The UI shows this before asking the user to confirm."""
    finding = _lookup_finding(scan_id, finding_id)
    remediation = get_remediation(finding.check_type)

    return {
        "available": remediation is not None,
        "enabled": config.REMEDIATION_ENABLED,
        "description": remediation.description if remediation else None,
    }


@app.post("/api/findings/{scan_id}/{finding_id}/remediate")
def remediate(scan_id: int, finding_id: int, user: str = Depends(require_user)) -> dict:
    if not config.REMEDIATION_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Remediation is disabled. Set REMEDIATION_ENABLED=true and grant the write permissions listed in the README.",
        )

    finding = _lookup_finding(scan_id, finding_id)
    remediation = get_remediation(finding.check_type)
    if remediation is None:
        raise HTTPException(status_code=422, detail=f"No automatic fix is available for {finding.check_type}.")

    try:
        message = remediation.apply(build_session(finding.region), finding)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except (ClientError, NoCredentialsError, ProfileNotFound) as e:
        raise HTTPException(status_code=502, detail=f"AWS rejected the fix: {e}")

    logger.info("User %s remediated %s on %s", user, finding.check_type, finding.resource_id)
    return {"ok": True, "message": message}


# Production/demo mode: serve the built React app if it exists. In dev, the Vite
# dev server serves the frontend and proxies /api/* here instead.
#
# Mounted LAST so it can't shadow any /api route above.
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")
