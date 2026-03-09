# PII-Safe PoC — GSoC 2026 C2SI

Privacy middleware that detects, redacts, and pseudonymizes PII 
before it reaches an LLM. Built as a proof-of-concept for the 
C2SI GSoC 2026 PII-Safe project.

## Live Demo

https://github.com/user-attachments/assets/eae47ab1-bd33-488c-b1b8-eff9f4486c00

## What It Does
Input → PII-Safe → Clean output to LLM.

## Key Features
- Policy-as-code (rules.yaml drives all decisions)
- Consistent pseudonymization across a session
- MCP server — plug into any MCP-compatible agent
- Risk scoring (0.0–1.0)
- FastAPI REST + React dashboard

## What's Not in the PoC (Full Project Scope)
- HuggingFace transformers for better NER
- Redis session persistence
- CLI batch tool
- Docker deployment
- LangChain/LangGraph integration examples
  
## Quick Start
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
