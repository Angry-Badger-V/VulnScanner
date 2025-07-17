# vulnscanner.py
import argparse
from scanners import registry
from report import Report

def main():
    parser = argparse.ArgumentParser(
        description="vulnscanner - Modular Vulnerability Scanner"
    )

    # add target and output args
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or URL"
    )

    parser.add_argument(
        "--output",
        default="report.json",
        help="Path to save the report"
    )

    # dynamically add scanner args
    for name, module in registry.items():
        parser.add_argument(
            f"--{name}",
            action="store_true",
            help=module.description
        )

    args = parser.parse_args()
    report = Report(target=args.target)

    for name, module in registry.items():
        if hasattr(args, name.replace("-", "_")):
            module.run(args.target, report)

    report.save_json(args.output)

if __name__ == "__main__":
    main()