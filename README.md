# Domain Intel 360 (React + FastAPI)

## Local Quick Start

1. Clone and enter project:

```bash
git clone https://github.com/Ash-26-J/work2.git
cd work2/webnet
```

2. Backend setup (Python):

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate    # Windows PowerShell
pip install -r requirements.txt
```

3. Set environment variables for API keys (Linux/macOS example):

```bash
export ABUSEIPDB_API_KEY=""
export ALIENVAULT_API_KEY=""
export VIRUSTOTAL_API_KEY=""
export IPQUALITYSCORE_API_KEY=""
export URLSCAN_API_KEY=""
export PULSEDIVE_API_KEY=""
export GREYNOISE_API_KEY=""
export VPNAPI_KEY=""
export CENSYS_API_ID=""
export CENSYS_API_SECRET=""
```

4. Run backend API:

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

5. Frontend setup and run (new terminal):

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

6. Open in browser:

- Frontend: `http://localhost:5173`
- Backend health: `http://localhost:8000/health`

## Backend (FastAPI)

1. Create/activate your Python environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Export API keys as environment variables:

- `ABUSEIPDB_API_KEY`
- `ALIENVAULT_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `IPQUALITYSCORE_API_KEY`
- `URLSCAN_API_KEY`
- `PULSEDIVE_API_KEY`
- `GREYNOISE_API_KEY`
- `VPNAPI_KEY`
- `CENSYS_API_ID` (optional, for passive port intelligence)
- `CENSYS_API_SECRET` (optional, for passive port intelligence)

Optional: install `nmap` to enable Nmap-based active scanning. If unavailable, the backend falls back to socket scanning.

4. Run backend:

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend (React + Vite)

1. Install dependencies:

```bash
cd frontend
npm install
```

2. Configure API base URL:

```bash
copy .env.example .env
```

3. Run frontend:

```bash
npm run dev
```

Open `http://localhost:5173`.

## API Endpoints

- `GET /health`
- `POST /analyze`

Request body for `/analyze`:

```json
{
  "domain": "google.com",
  "active_scan": false
}
```
