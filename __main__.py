"""
CLI entrypoint: python -m sqlbase [scan|predict|remediate] ...
Cross-platform: Linux, Windows, macOS.
"""
import argparse
import json
import sys
from pathlib import Path


def cmd_scan(args) -> int:
    from sqlbase.scanner import SQLInjectionScanner
    scanner = SQLInjectionScanner()
    path = Path(args.path).resolve()
    results = scanner.scan_path(path, extensions=args.extensions)
    out = json.dumps(results, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {len(results)} findings to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0 if not args.fail_on_findings or len(results) == 0 else 1


def cmd_predict(args) -> int:
    from sqlbase.predictor import VulnerabilityPredictor
    predictor = VulnerabilityPredictor()
    result = predictor.predict_vulnerability_likelihood(Path(args.path))
    print(json.dumps(result, indent=2))
    return 0


def cmd_remediate(args) -> int:
    from sqlbase.remediation import RemediationKnowledgeBase
    kb = RemediationKnowledgeBase()
    r = kb.get_remediation(args.type, args.language)
    print(json.dumps(r, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLbase security toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    # scan
    p_scan = sub.add_parser("scan", help="Scan path for SQL injection patterns")
    p_scan.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    p_scan.add_argument("-o", "--output", metavar="FILE", help="Write JSON report to FILE (cross-platform path)")
    p_scan.add_argument("--fail-on-findings", action="store_true", help="Exit 1 if any finding")
    p_scan.add_argument("--extensions", nargs="+", default=[".py", ".java", ".js", ".ts", ".php", ".rb", ".go", ".cs"], help="File extensions")
    p_scan.set_defaults(func=cmd_scan)
    # predict
    p_predict = sub.add_parser("predict", help="Predict vulnerability likelihood")
    p_predict.add_argument("path", nargs="?", default=".", help="File or directory")
    p_predict.set_defaults(func=cmd_predict)
    # remediate
    p_rem = sub.add_parser("remediate", help="Get remediation for vulnerability type + language")
    p_rem.add_argument("type", help="e.g. SQL_INJECTION")
    p_rem.add_argument("language", help="e.g. python, java")
    p_rem.set_defaults(func=cmd_remediate)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
