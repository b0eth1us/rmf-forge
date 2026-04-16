from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine, Base
from app.api.routes import projects, findings, consolidation, stig, zap, exports

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RMF Forge API",
    description="DoD RMF compliance scan consolidation — air-gapped, CUI-safe",
    version="0.1.0",
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router,      prefix="/api/projects",     tags=["Projects"])
app.include_router(findings.router,      prefix="/api/findings",     tags=["Findings"])
app.include_router(consolidation.router, prefix="/api/consolidate",  tags=["Consolidation"])
app.include_router(stig.router,          prefix="/api/stig",         tags=["STIG"])
app.include_router(zap.router,           prefix="/api/zap",          tags=["ZAP"])
app.include_router(exports.router,       prefix="/api/export",       tags=["Export"])

@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "version": "0.1.0"}
