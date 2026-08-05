import argparse
import os
import sys

from . import __version__
from .report import CONFIDENCE_RANK, print_json, print_report
from .scanner import scan_path


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a directory for hardcoded secrets using regex "
                    "patterns and entropy analysis.",
    )
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print results as JSON instead of the usual report",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        help="only report findings at this confidence or above (default: low)",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="skip entropy analysis and only use the regex patterns",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="print matched values in full instead of masking them",
    )
    parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="scan files that .gitignore excludes",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def filter_by_confidence(findings, minimum):
    cutoff = CONFIDENCE_RANK[minimum]
    return [f for f in findings if CONFIDENCE_RANK[f.confidence] <= cutoff]


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not os.path.exists(args.path):
        print("error: no such file or directory: %s" % args.path, file=sys.stderr)
        return 2

    findings, scanned = scan_path(
        args.path,
        use_entropy=not args.no_entropy,
        use_gitignore=not args.no_gitignore,
    )
    findings = filter_by_confidence(findings, args.min_confidence)

    if args.json:
        print_json(findings, scanned, show_secrets=args.show_secrets)
    else:
        print_report(findings, scanned, show_secrets=args.show_secrets)

    # Non-zero exit when something turned up, so this can gate a CI step.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
