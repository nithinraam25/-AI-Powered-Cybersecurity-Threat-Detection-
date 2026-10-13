"""Command-line training tool for the NSL-KDD binary Random Forest baseline.

Usage:
    python -m threat_detection.detection.train_cli [DATA_PATH] [--output OUTPUT_PATH] [--val-fraction 0.2] [--seed 42]
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from threat_detection.config import config
from threat_detection.detection.trainer import train_binary_model


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser for model training."""
    parser = argparse.ArgumentParser(
        description="Train baseline Random Forest binary classifier on NSL-KDD data.",
        prog="python -m threat_detection.detection.train_cli",
    )
    parser.add_argument(
        "filepath",
        nargs="?",
        default=None,
        help="Path to training dataset file (defaults to data/raw/KDDTrain+.txt)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Destination path for serialized model artifact (defaults to models/baseline_rf_binary.joblib)",
    )
    parser.add_argument(
        "--val-fraction",
        type=float,
        default=0.2,
        help="Validation split fraction (default: 0.2)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=config.RANDOM_SEED,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--strict-labels",
        action="store_true",
        help="Reject uncatalogued attack labels instead of treating as 'attack'",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for binary model training.

    Returns:
        0 on successful training and artifact serialization.
        1 on missing file, validation failure, or training error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    target_data = Path(args.filepath) if args.filepath else config.DEFAULT_TRAIN_PATH
    default_artifact_path = config.MODELS_DIR / "baseline_rf_binary.joblib"
    output_path = Path(args.output) if args.output else default_artifact_path

    print(f"Starting training workflow using dataset: '{target_data}'")
    print(f"Target artifact destination: '{output_path}'")

    if not target_data.exists():
        print(
            f"[FATAL ERROR] Dataset file not found at: '{target_data}'. "
            "Please provide a valid NSL-KDD dataset file to train.",
            file=sys.stderr,
        )
        return 1

    try:
        _, summary = train_binary_model(
            data=target_data,
            val_fraction=args.val_fraction,
            random_seed=args.seed,
            output_path=output_path,
            on_unknown_labels="error" if args.strict_labels else "attack",
        )
    except FileNotFoundError as e:
        print(f"[FATAL ERROR] File not found: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"[FATAL ERROR] Training data or schema error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[FATAL ERROR] Unexpected exception during training: {e}", file=sys.stderr)
        return 1

    print()
    print(summary.summary())
    print("\n[SUCCESS] Baseline binary model trained and persisted successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
