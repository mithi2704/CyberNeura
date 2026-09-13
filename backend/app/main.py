"""
CyberNeura Backend — FastAPI Application Entry Point
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.utils.logger import get_logger
from app.api.routes import (
    health, scan, scans, dashboard, threats,
    insights, notifications, settings as settings_router,
    users, chat, reports, intelligence, risk, evidence, agent, realtime, extension, media,
)

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.app_name} v{settings.app_version} [{settings.app_env}]")
    # Pre-load ML model at startup
    from app.ml.predictor import predict, get_model_version
    _ = predict({"uses_https": 1, "url_length": 20})  # warm up
    logger.info(f"ML model ready: {get_model_version()}")
    yield
    logger.info("CyberNeura Backend shutting down")


app = FastAPI(
    title="CyberNeura Backend API",
    description=(
        "AI-powered URL Threat Intelligence & Security Operations Platform.\n\n"
        "Authenticate using Firebase ID tokens as `Bearer <token>` in the Authorization header."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|chrome-extension://[a-z0-9]+)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global exception handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "INTERNAL_ERROR", "message": "An unexpected error occurred"},
    )


# ── Route Registration ────────────────────────────────────────────────────────
# Core
app.include_router(health.router)
app.include_router(scan.router)             # POST /scan
app.include_router(scans.router)            # GET/DELETE /scans
app.include_router(dashboard.router)        # GET /dashboard/*
app.include_router(threats.router)          # GET/DELETE /threats
app.include_router(insights.router)         # GET /insights
app.include_router(notifications.router)    # GET/POST /notifications
app.include_router(settings_router.router)  # GET/PUT /settings
app.include_router(users.router)            # GET/PATCH/DELETE /users
app.include_router(chat.router)             # POST/GET /chat
app.include_router(reports.router)          # GET /reports
app.include_router(intelligence.router)     # /intelligence/*
app.include_router(risk.router)             # /risk/*
app.include_router(evidence.router)         # /evidence/*
app.include_router(agent.router)            # /agent/*
app.include_router(realtime.router)         # /realtime/*
app.include_router(extension.router)        # /extension/*
app.include_router(media.router)            # /media/*

# ── /api/v1 versioned aliases ─────────────────────────────────────────────────
from fastapi import APIRouter
v1 = APIRouter(prefix="/api/v1")
v1.include_router(scan.router)
v1.include_router(scans.router)
v1.include_router(dashboard.router)
v1.include_router(threats.router)
v1.include_router(insights.router)
v1.include_router(notifications.router)
v1.include_router(settings_router.router)
v1.include_router(users.router)
v1.include_router(chat.router)
v1.include_router(reports.router)
v1.include_router(intelligence.router)
v1.include_router(risk.router)
v1.include_router(evidence.router)
v1.include_router(agent.router)
v1.include_router(realtime.router)
v1.include_router(extension.router)
v1.include_router(media.router)
app.include_router(v1)




@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
    }
