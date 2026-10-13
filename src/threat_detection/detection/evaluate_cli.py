"""Command-line evaluation tool for frozen threat detection models.

Usage:
    python -m threat_detection.detection.evaluate_cli [TEST_PATH] [--model MODEL_PATH] [--json-output OUTPUT_JSON]
"""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from threat_detection.config import config
from threat_detection.detection.evaluator import evaluate_model
from threat_detection.detection.trainer import ThreatDetectionArtifact


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser for model evaluation."""
    parser = argparse.ArgumentParser(
        description="Evaluate frozen baseline Random Forest binary classifier on NSL-KDD test data.",
        prog="python -m threat_detection.detection.evaluate_cli",
    )
    parser.add_argument(
        "filepath",
        nargs="?",
        default=None,
        help="Path to test dataset file (defaults to data/raw/KDDTest+.txt)",
    )
    parser.add_argument(
        "--model",
        "-m",
        default=None,
        help="Path to frozen model artifact (defaults to models/baseline_rf_binary.joblib)",
    )
    parser.add_argument(
        "--strict-labels",
        action="store_true",
        help="Raise error on uncatalogued attack labels instead of treating as novel intrusions ('attack')",
    )
    parser.add_argument(
        "--json-output",
        "-j",
        default=None,
        help="Optional destination path to save evaluation metrics as JSON",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for frozen model evaluation.

    Returns:
        0 on successful evaluation.
        1 on missing file, validation failure, or evaluation error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    default_test_path = config.RAW_DATA_DIR / "KDDTest+.txt"
    target_data = Path(args.filepath) if args.filepath else default_test_path

    default_model_path = config.MODELS_DIR / "baseline_rf_binary.joblib"
    model_path = Path(args.model) if args.model else default_model_path

    print(f"Loading frozen model artifact: '{model_path}'")
    if not model_path.exists():
        print(
            f"[FATAL ERROR] Model artifact not found at: '{model_path}'. "
            "Please ensure the baseline model has been trained before evaluation.",
            file=sys.stderr,
        )
        return 1

    try:
        artifact = ThreatDetectionArtifact.load(model_path)
    except Exception as e:
        print(f"[FATAL ERROR] Failed to load model artifact: {e}", file=sys.stderr)
        return 1

    print(f"Evaluating frozen model on dataset: '{target_data}'")
    if not target_data.exists():
        print(
            f"[FATAL ERROR] Test dataset file not found at: '{target_data}'.",
            file=sys.stderr,
        )
        return 1

    try:
        metrics = evaluate_model(
            artifact=artifact,
            data=target_data,
            on_unknown_labels="error" if args.strict_labels else "attack",
            model_source_desc=str(model_path),
        )
    except FileNotFoundError as e:
        print(f"[FATAL ERROR] File not found: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"[FATAL ERROR] Evaluation schema or target error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[FATAL ERROR] Unexpected exception during evaluation: {e}", file=sys.stderr)
        return 1

    print()
    print(metrics.summary())

    if args.json_output:
        out_path = Path(args.json_output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(metrics.to_dict(), f, indent=2)
        print(f"\n[INFO] Evaluation metrics saved to: '{out_path}'")

    print("\n[SUCCESS] Model evaluation completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
