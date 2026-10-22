"""Run CE scans; scanner success and security findings are separate outcomes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "generated"


def main():
    global OUT
    parser = argparse.ArgumentParser()
    parser.add_argument("--custom-only", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=OUT)
    args = parser.parse_args()
    OUT = args.output_dir.resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0", PYTHONUTF8="1")
    local_exe = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    executable = [str(local_exe) if local_exe.exists() else (shutil.which("semgrep") or "semgrep")]
    version = subprocess.run(executable + ["--version"], capture_output=True, text=True, env=env)
    if version.returncode:
        print("FAIL: Semgrep executable could not start", version.stderr)
        return 2
    groups = {"custom": str(ROOT / "sast" / "lab-rules.yml")}
    if not args.custom_only:
        groups = {"registry": str(ROOT / "sast" / "registry-python.yml"), **groups}
    summary = []
    for variant in ("app", "app-fixed"):
        for group, config in groups.items():
            stem = OUT / f"semgrep-{variant}-{group}"
            command = executable + ["scan", "--oss-only", "--metrics=off", "--disable-version-check", "--strict",
                                    "--config", config, "--json-output", str(stem) + ".json",
                                    "--sarif-output", str(stem) + ".sarif", variant]
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
            Path(str(stem) + ".log").write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
            report_path = Path(str(stem) + ".json")
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
            scanned = report.get("paths", {}).get("scanned", [])
            valid = result.returncode == 0 and not report.get("errors") and bool(scanned)
            row = {"variant": variant, "group": group, "exit_code": result.returncode,
                   "technical_success": valid, "findings": len(report.get("results", [])),
                   "files_scanned": len(scanned), "errors": report.get("errors", []),
                   "config_sha256": hashlib.sha256(Path(config).read_bytes()).hexdigest() if Path(config).exists() else None}
            summary.append(row)
            print(f"{'PASS' if valid else 'FAIL'} {variant}/{group}: findings={row['findings']}, scanned={row['files_scanned']}, exit={result.returncode}", flush=True)
    source_hashes = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                     for variant in ('app', 'app-fixed') for p in (ROOT / variant).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts}
    (OUT / "semgrep-summary.json").write_text(json.dumps({"version": version.stdout.strip(), "utc": datetime.now(timezone.utc).isoformat(), "source_sha256": source_hashes, "results": summary}, indent=2), encoding="utf-8")
    return 0 if all(row["technical_success"] for row in summary) else 2


if __name__ == "__main__":
    sys.exit(main())
