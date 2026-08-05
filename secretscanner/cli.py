import argparse
import sys

from . import __version__


def build_parser():
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a directory for hardcoded secrets.",
    )
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    print("would scan:", args.path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
