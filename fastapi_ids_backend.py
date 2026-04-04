from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from intrusion_detection import IntrusionDetector


LOGGER = logging.getLogger("ids_api")
DEFAULT_MODEL_PATH = Path(os.getenv("IDS_MODEL_PATH", "model.pkl")).expanduser()


class DetectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    length: int = Field(..., ge=0, description="Packet length in bytes.")
    protocol: int = Field(..., ge=0, description="Encoded protocol identifier.")
    time_diff: float = Field(..., ge=0.0, description="Inter-arrival time in seconds.")
    packet_rate: float = Field(..., ge=0.0, description="Packets per second.")
    avg_length: float = Field(..., ge=0.0, description="Rolling average packet length.")


class DetectionResponse(BaseModel):
    prediction: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool


def _configure_logging() -> None:
    if logging.getLogger().handlers:
        return

    logging.basicConfig(
        level=os.getenv("IDS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def _load_detector_from_env() -> IntrusionDetector:
    model_path = DEFAULT_MODEL_PATH.resolve()
    return IntrusionDetector(model_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    app.state.detector = None
    app.state.model_path = str(DEFAULT_MODEL_PATH)

    try:
        app.state.detector = _load_detector_from_env()
        app.state.model_path = str(app.state.detector.model_path)
        LOGGER.info("Intrusion detection model ready: %s", app.state.model_path)
    except Exception:
        LOGGER.exception("Failed to load intrusion detection model during startup")

    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Intrusion Detection API",
        version="1.0.0",
        description="FastAPI backend for ML-powered intrusion detection.",
        lifespan=lifespan,
    )

    @app.exception_handler(ValueError)
    async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("Unhandled application error", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health_check(request: Request) -> HealthResponse:
        return HealthResponse(
            status="ok",
            model_loaded=request.app.state.detector is not None,
        )

    @app.post("/detect", response_model=DetectionResponse, tags=["detection"])
    async def detect_intrusion(payload: DetectionRequest, request: Request) -> DetectionResponse:
        detector: IntrusionDetector | None = request.app.state.detector
        if detector is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Model is not loaded. Verify IDS_MODEL_PATH points to a valid "
                    ".pkl or .joblib model file."
                ),
            )

        prediction = detector.predict(payload.model_dump())
        return DetectionResponse(prediction=prediction)

    return app


app = create_app()
