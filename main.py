"""AI-Powered Cybersecurity Threat Detection System.

Main application entry point.
Phase 1: Project Foundation.
"""

import sys
from pathlib import Path

# Add src to sys.path to enable local discovery when run directly
SRC_PATH = Path(__file__).resolve().parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from threat_detection import __version__
from threat_detection.config import config


def main() -> None:
    """Print project foundation status without claiming detection or training."""
    print("=" * 70)
    print("AI-Powered Cybersecurity Threat Detection System")
    print(f"Version: {__version__}")
    print("=" * 70)
    print("Status: Project foundation established (Phase 1).")
    print(f"Base Directory: {config.BASE_DIR}")
    print(f"Data Directory: {config.DATA_DIR}")
    print(f"Models Directory: {config.MODELS_DIR}")
    print("Note: Detection models and training pipelines are planned for future phases.")
    print("=" * 70)


if __name__ == "__main__":
    main()
