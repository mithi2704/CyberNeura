"""
CyberNeura ML Microservice — Standalone FastAPI Application.
Provides decoupled high-performance ML inference for URL and AI Image detection.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ml_service.app.routes import prediction_routes, health_routes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ml_service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberNeura ML Microservice on port 8001...")
    yield
    logger.info("CyberNeura ML Microservice stopped.")


app = FastAPI(
    title="CyberNeura ML Microservice",
    version="2.1.0",
    description="Dedicated microservice for URL Threat Detection & AI Image Classification",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_routes.router)
app.include_router(prediction_routes.router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ml_service.app.main:app", host="0.0.0.0", port=8001, reload=True)

