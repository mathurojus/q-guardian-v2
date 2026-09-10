# Q-Guardian v2 — Preview Run Doc

Full-stack app: FastAPI backend (port 8000) + Vite/React frontend (port 5173).
The frontend proxies `/api` to `http://localhost:8000` (see `frontend/vite.config.js`).

## Prerequisites

- Backend venv at `backend/.venv` (Windows: `backend/.venv/Scripts/python.exe`).
  Missing? Create it and install `backend/requirements.txt`:
  `python -m venv backend/.venv` then
  `backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt`
- `backend/.env` — copy from `backend/.env.example` if absent. It supplies
  `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH` (bcrypt), and CORS
  origins. Required for login to work.
- Frontend deps installed (`frontend/node_modules`). Missing? Run
  `npm install` inside `frontend/`.
- A seeded demo DB (`backend/qguardian.db`) is optional but recommended.
  Reseed with: `cd backend && ./.venv/Scripts/python.exe ../demo/seed_demo.py --wipe`

## How to reproduce the artifacts (env files)

1. Copy `backend/.env.example` to `backend/.env` (or copy the existing
   `backend/.env` from the main checkout if this is a fresh worktree — it is
   gitignored and never committed). Do not symlink; adapt values if ports change.
2. There are no other uncommitted env/config artifacts required to run.

## How to run the server

### Backend (port 8000) — detached on Windows

```powershell
powershell -NoProfile -Command "(Start-Process -FilePath 'C:\Users\Ojus\Desktop\sih\backend\.venv\Scripts\python.exe' -ArgumentList '-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8000' -WorkingDirectory 'C:\Users\Ojus\Desktop\sih\backend' -RedirectStandardOutput '<log>' -RedirectStandardError '<log>.err' -WindowStyle Hidden -PassThru).Id"
```

Note: Start-Process with `-PassThru` holds the shell open until the child
exits, so the command appears to hang — that is expected. Verify with
`netstat -ano | grep ':8000 ' | grep LISTEN` and
`curl http://127.0.0.1:8000/docs` (expect HTTP 200).

### Frontend (port 5173) — detached on Windows

```powershell
powershell -NoProfile -Command "(Start-Process -FilePath 'npm.cmd' -ArgumentList 'run','dev' -WorkingDirectory 'C:\Users\Ojus\Desktop\sih\frontend' -RedirectStandardOutput '<log>' -RedirectStandardError '<log>.err' -WindowStyle Hidden -PassThru).Id"
```

Same hang-on-launch behavior is expected. Verify with
`netstat -ano | grep ':5173 ' | grep LISTEN` and
`curl http://localhost:5173/` (expect HTTP 200).

### Log in

Demo credentials (shown on the login screen): user `qguardian_admin`,
password `QGuardian@2026`.

## Ports

Default 8000 (backend) and 5173 (frontend). If either is taken, change the
backend `--port` and the frontend via `VITE_PORT`/`VITE_BACKEND_URL` env or
`vite.config.js` proxy target.