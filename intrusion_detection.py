from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Mapping

import joblib
import pandas as pd


LOGGER = logging.getLogger(__name__)

FEATURE_COLUMNS = ["length", "protocol", "time_diff", "packet_rate", "avg_length"]
FEATURE_ALIASES = {
    "length": ["length", "packet_length"],
    "protocol": ["protocol"],
    "time_diff": ["time_diff", "inter_arrival_time"],
    "packet_rate": ["packet_rate"],
    "avg_length": ["avg_length", "rolling_avg_packet_length"],
}

_DEFAULT_DETECTOR: "IntrusionDetector | None" = None


def _load_model(model_path: str | Path) -> Any:
    resolved_path = Path(model_path).expanduser().resolve()
    if not resolved_path.is_file():
        raise FileNotFoundError(f"Model file not found: {resolved_path}")

    if resolved_path.suffix.lower() in {".joblib", ".jl"}:
        return joblib.load(resolved_path)

    with resolved_path.open("rb") as model_file:
        return pickle.load(model_file)


def _normalize_features(features: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}

    for canonical_name, aliases in FEATURE_ALIASES.items():
        for alias in aliases:
            if alias in features:
                normalized[canonical_name] = features[alias]
                break
        else:
            raise ValueError(
                f"Missing required feature '{canonical_name}'. Accepted names: {aliases}"
            )

    return normalized


class IntrusionDetector:
    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path).expanduser().resolve()
        self.model = _load_model(self.model_path)
        LOGGER.info("Loaded intrusion detection model from %s", self.model_path)

    def _prepare_input(self, features: Mapping[str, Any]) -> pd.DataFrame:
        normalized = _normalize_features(features)
        return pd.DataFrame([normalized], columns=FEATURE_COLUMNS)

    def predict(self, features: Mapping[str, Any]) -> str:
        model_input = self._prepare_input(features)
        raw_prediction = self.model.predict(model_input)[0]
        prediction = self._map_prediction(raw_prediction)

        if prediction == "Intrusion":
            LOGGER.warning(
                "Intrusion detected for features: protocol=%s length=%s time_diff=%s packet_rate=%s avg_length=%s",
                model_input.at[0, "protocol"],
                model_input.at[0, "length"],
                model_input.at[0, "time_diff"],
                model_input.at[0, "packet_rate"],
                model_input.at[0, "avg_length"],
            )
        else:
            LOGGER.info("Normal traffic prediction generated")

        return prediction

    @staticmethod
    def _map_prediction(raw_prediction: Any) -> str:
        if isinstance(raw_prediction, str):
            normalized = raw_prediction.strip().lower()
            if normalized in {"intrusion", "attack", "malicious", "anomaly", "1"}:
                return "Intrusion"
            return "Normal"

        if isinstance(raw_prediction, (int, float, bool)):
            return "Intrusion" if int(raw_prediction) == 1 else "Normal"

        return "Intrusion" if str(raw_prediction).strip().lower() == "intrusion" else "Normal"


def load_detector(model_path: str | Path) -> IntrusionDetector:
    return IntrusionDetector(model_path)


def configure_default_model(model_path: str | Path) -> None:
    global _DEFAULT_DETECTOR
    _DEFAULT_DETECTOR = IntrusionDetector(model_path)


def detect(features: Mapping[str, Any]) -> str:
    """
    Predict whether a feature vector represents normal traffic or an intrusion.

    Call `configure_default_model(model_path)` once during application startup
    before using this function in an API or service context.
    """
    if _DEFAULT_DETECTOR is None:
        raise RuntimeError(
            "No default model configured. Call configure_default_model(model_path) first."
        )

    return _DEFAULT_DETECTOR.predict(features)
