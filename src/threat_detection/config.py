"""Project configuration management.

Provides structured access to directory paths, threshold parameters,
and runtime settings.
"""

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class ProjectConfig:
    """Project-wide paths and configuration settings."""

    # Base workspace directory
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent

    # Data paths
    DATA_DIR: Path = BASE_DIR / "data"
    RAW_DATA_DIR: Path = DATA_DIR / "raw"
    PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
    SAMPLE_DATA_DIR: Path = DATA_DIR / "sample"
    DEFAULT_TRAIN_FILE: str = "KDDTrain+.txt"
    DEFAULT_TEST_FILE: str = "KDDTest+.txt"
    DEFAULT_TRAIN_PATH: Path = RAW_DATA_DIR / "KDDTrain+.txt"
    DEFAULT_TEST_PATH: Path = RAW_DATA_DIR / "KDDTest+.txt"

    # Artifacts & Outputs
    MODELS_DIR: Path = BASE_DIR / "models"
    OUTPUTS_DIR: Path = BASE_DIR / "outputs"
    REPORTS_DIR: Path = OUTPUTS_DIR / "reports"
    FIGURES_DIR: Path = OUTPUTS_DIR / "figures"
    LOGS_DIR: Path = OUTPUTS_DIR / "logs"
    DATABASE_PATH: Path = OUTPUTS_DIR / "threat_events.db"

    # Threat Scoring Thresholds
    CRITICAL_THRESHOLD: float = 85.0
    HIGH_THRESHOLD: float = 70.0
    MEDIUM_THRESHOLD: float = 45.0
    LOW_THRESHOLD: float = 20.0

    # Default random seed
    RANDOM_SEED: int = 42


config = ProjectConfig()
