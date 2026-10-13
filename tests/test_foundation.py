"""Foundation tests for Phase 1 project scaffolding."""

import threat_detection
from threat_detection.config import config


def test_package_metadata() -> None:
    """Verify package name and semantic version format."""
    assert threat_detection.__version__ == "0.1.0"


def test_project_config_paths() -> None:
    """Verify standard paths configured in ProjectConfig."""
    assert config.BASE_DIR.exists()
    assert config.DATA_DIR.name == "data"
    assert config.MODELS_DIR.name == "models"
    assert config.OUTPUTS_DIR.name == "outputs"
    assert config.CRITICAL_THRESHOLD > config.HIGH_THRESHOLD
