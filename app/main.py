from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.api.routes import router

app = FastAPI(
    title="VBG Defense Orchestrator",
    description=(
        "SIEM alert correlation, MITRE ATT&CK-mapped detection coverage, "
        "asset-weighted vulnerability prioritization, and SOAR playbook execution."
    ),
)

app.include_router(router)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin")
def admin_console():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/health")
def health():
    return {"status": "ok"}
