# --- stage 1: build the React SPA ---
FROM node:22-slim AS frontend

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --- stage 2: python runtime, serving the API + the built SPA ---
FROM python:3.12-slim

WORKDIR /app

# No native build deps needed: password hashing uses stdlib PBKDF2 rather than
# bcrypt/argon2, precisely so this image needs no compiler toolchain.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY api/ ./api/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/

# api/main.py mounts this via StaticFiles, so the whole app is one process on one
# port -- no nginx, no second service.
COPY --from=frontend /app/frontend/dist ./frontend/dist

# users.json + scan_history.json live here; mount a volume to persist them.
RUN mkdir -p /app/data

EXPOSE 8000

# SINGLE worker, deliberately. Scan state lives in process-module globals and the
# scheduler starts per-process -- N workers would mean N inconsistent copies of the
# current scan plus N duplicate nightly scans and alert emails.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
