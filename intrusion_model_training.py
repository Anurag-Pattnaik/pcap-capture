from __future__ import annotations

import argparse
import logging
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


LOGGER = logging.getLogger(__name__)

REQUIRED_FEATURE_ALIASES = {
    "length": ["length", "packet_length"],
    "protocol": ["protocol"],
    "time_diff": ["time_diff", "inter_arrival_time"],
    "packet_rate": ["packet_rate"],
    "avg_length": ["avg_length", "rolling_avg_packet_length"],
}
LABEL_COLUMN = "label"


def _resolve_columns(dataframe: pd.DataFrame) -> dict[str, str]:
    resolved: dict[str, str] = {}

    for canonical_name, aliases in REQUIRED_FEATURE_ALIASES.items():
        for candidate in aliases:
            if candidate in dataframe.columns:
                resolved[canonical_name] = candidate
                break
        else:
            raise ValueError(
                f"Missing required feature column for '{canonical_name}'. "
                f"Accepted names: {aliases}"
            )

    if LABEL_COLUMN not in dataframe.columns:
        raise ValueError(f"Missing required label column: '{LABEL_COLUMN}'")

    return resolved


def _build_pipeline() -> Pipeline:
    numeric_features = ["length", "time_diff", "packet_rate", "avg_length"]
    categorical_features = ["protocol"]

    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
        ]
    )
    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ]
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=200,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def train_model(data_path: str | Path):
    """
    Train a Random Forest intrusion detection model from a CSV dataset.

    Parameters
    ----------
    data_path:
        Path to a CSV file containing feature columns and a `label` column.

    Returns
    -------
    sklearn.pipeline.Pipeline
        Trained preprocessing and classification pipeline.
    """
    dataset_path = Path(data_path).expanduser().resolve()
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    LOGGER.info("Loading dataset from %s", dataset_path)
    dataframe = pd.read_csv(dataset_path)
    resolved_columns = _resolve_columns(dataframe)

    model_frame = dataframe[
        [
            resolved_columns["length"],
            resolved_columns["protocol"],
            resolved_columns["time_diff"],
            resolved_columns["packet_rate"],
            resolved_columns["avg_length"],
            LABEL_COLUMN,
        ]
    ].rename(
        columns={
            resolved_columns["length"]: "length",
            resolved_columns["protocol"]: "protocol",
            resolved_columns["time_diff"]: "time_diff",
            resolved_columns["packet_rate"]: "packet_rate",
            resolved_columns["avg_length"]: "avg_length",
        }
    )

    X = model_frame[["length", "protocol", "time_diff", "packet_rate", "avg_length"]]
    y = model_frame[LABEL_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )

    model = _build_pipeline()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    matrix = confusion_matrix(y_test, y_pred)

    print(f"Accuracy: {accuracy:.4f}")
    print("Confusion Matrix:")
    print(matrix)

    model_path = dataset_path.with_name(f"{dataset_path.stem}_rf_model.joblib")
    joblib.dump(model, model_path)
    LOGGER.info("Saved trained model to %s", model_path)

    return model


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a Random Forest intrusion detection model from a CSV dataset."
    )
    parser.add_argument("data_path", help="Path to the training CSV dataset.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    train_model(args.data_path)


if __name__ == "__main__":
    main()
