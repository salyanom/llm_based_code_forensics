# Tree Sitter Demo - Code Forensics Platform

This repository contains a local security forensics platform that combines:

- AST parsing with Tree-sitter
- LLM-assisted vulnerability verification and patch suggestions
- RAG-based threat intelligence correlation (Qdrant-backed)
- FastAPI APIs and PowerShell helper scripts for scanning workflows

## Project Layout

- `main.py`: FastAPI app and CLI entry point
- `agents/`: detection, correlation, verification, and patch agents
- `services/`: parser, LLM, and RAG services
- `database/`: persistence models for scan sessions and feedback
- `knowledge/`: local vulnerability intelligence datasets
- `code_samples/`: sample files for quick test scans
- `tree-sitter-c/`: embedded Tree-sitter C grammar source
- `start-dev.ps1` / `stop-dev.ps1`: local dev startup and shutdown scripts
- `scan-pretty.ps1`: API scan helper with human-friendly output
- `interactive-console.ps1`: interactive command loop for scan + ask workflows

## Prerequisites

- Windows PowerShell
- Python 3.10+
- Docker Desktop (optional, for Qdrant)

## Local Setup (Windows)

```powershell
cd "Tree Sitter Demo"

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

Copy-Item .env.example .env
```

## Start the Project

```powershell
powershell -ExecutionPolicy Bypass -File .\start-dev.ps1
```

This starts:

- Qdrant (via `docker-compose.qdrant.yml`, if Docker is available)
- FastAPI server at `http://localhost:8000`

## Common Commands

Run a scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan-pretty.ps1 -Folder code_samples -Query "scan all"
```

Run interactive console:

```powershell
powershell -ExecutionPolicy Bypass -File .\interactive-console.ps1
```

Stop API + Qdrant:

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-dev.ps1
```

## API Endpoints

- `GET /health`
- `POST /rag/refresh`
- `POST /scan`
- `POST /scan/upload`
- `GET /scan/{scan_id}`
- `GET /scans`
- `POST /feedback`
- `POST /assistant/ask`

### Request Models

`POST /scan`

```json
{
  "folder": "code_samples",
  "query": "scan all",
  "generate_patches": true
}
```

`POST /assistant/ask`

```json
{
  "prompt": "Which findings are highest risk?",
  "scan_id": null,
  "top_findings": 5
}
```

## Publish to GitHub

1. Initialize local git repository:

```powershell
git init
git add .
git commit -m "Initial commit: code forensics platform"
```

2. Create a GitHub repo and push (replace `<YOUR_REPO_URL>`):

```powershell
git branch -M main
git remote add origin <YOUR_REPO_URL>
git push -u origin main
```

Example remote URL formats:

- `https://github.com/<username>/<repo>.git`
- `git@github.com:<username>/<repo>.git`
