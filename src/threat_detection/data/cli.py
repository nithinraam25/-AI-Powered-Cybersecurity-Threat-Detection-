"""Command-line validation tool for NSL-KDD dataset files.

Usage:
    python -m threat_detection.data.cli [FILEPATH] [--variant standard_42|with_difficulty_43]
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from threat_detection.config import config
from threat_detection.data.loader import load_nsl_kdd
from threat_detection.data.schema import NSLKDDVariant
from threat_detection.data.validator import validate_nsl_kdd


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Validate local NSL-KDD dataset file integrity and schema conformance.",
        prog="python -m threat_detection.data.cli",
    )
    parser.add_argument(
        "filepath",
        nargs="?",
        default=None,
        help="Path to NSL-KDD file (defaults to data/raw/KDDTrain+.txt)",
    )
    parser.add_argument(
        "--variant",
        choices=["standard_42", "with_difficulty_43"],
        default=None,
        help="Optional strict schema variant enforcement",
    )
    parser.add_argument(
        "--strict-labels",
        action="store_true",
        help="Treat uncatalogued attack labels as fatal errors instead of warnings",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for dataset validation.

    Returns:
        0 if validation succeeds and the dataset is valid.
        1 if file loading fails or fatal validation errors are detected.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    target_path = Path(args.filepath) if args.filepath else config.RAW_DATA_DIR / "KDDTrain+.txt"
    variant = NSLKDDVariant(args.variant) if args.variant else None

    print(f"Auditing NSL-KDD dataset target: '{target_path}'")

    try:
        df = load_nsl_kdd(filepath=target_path, schema_variant=variant)
    except FileNotFoundError as e:
        print(f"[FATAL ERROR] File not found: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"[FATAL ERROR] Data loading failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[FATAL ERROR] Unexpected exception reading file: {e}", file=sys.stderr)
        return 1

    report = validate_nsl_kdd(
        df,
        expected_variant=variant,
        allow_unknown_labels=not args.strict_labels,
    )

    print()
    print(report.summary())

    if report.is_valid:
        print("\n[SUCCESS] Dataset schema and integrity audit passed.")
        return 0
    else:
        print("\n[FAILED] Dataset failed schema and integrity audit.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
