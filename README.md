# PII-Safe

## Run Backend API

```bash
cd /home/srisrinivasa/coding/modelcontextproj
uv sync
uv run uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

## Run MCP Server

```bash
cd /home/srisrinivasa/coding/modelcontextproj
uv run python -m mcp_server.server
```

## Run Frontend Dashboard

```bash
cd /home/srisrinivasa/coding/modelcontextproj/frontend
cp .env.example .env
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

The frontend calls `http://127.0.0.1:8000` by default.

## Frontend Features

- Upload `.txt`, `.log`, or `.json` files
- Paste raw logs manually
- Choose operation: `analysis`, `export`, `storage`, `logging`
- Visual output highlighting:
  - redaction in red
  - pseudonymized tokens in amber
- Rule-based explanation per entity, including inferred `rule #`
- Risk score chart and action distribution pie chart
- AI log summary panel (local deterministic summary)
- One-click copy of sanitized output
- Audit log stage display

## Notes

- If you do not have Node installed, install Node.js 18+ first.
- Backend CORS is already enabled for local development.
