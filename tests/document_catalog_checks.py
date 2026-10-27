"""Check the fixed document catalog over real HTTP without WAF."""
import argparse
from html import unescape
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

from http_checks import Checks


def run(base):
    checks = Checks(base, "fixed", "linux")
    response = checks.post(checks.alice, "/login", {"username": "alice", "password": "Alice-Lab-2026!"})
    checks.record("login", response.status_code == 200 and urlsplit(response.url).path == "/",
                  "Authenticated local test session")
    document_root = Path(__file__).resolve().parents[1] / "app-fixed/documents"
    expected = {path.name: path.read_bytes() for path in document_root.iterdir() if path.is_file()}
    for page in ("/", "/documents"):
        response = checks.get(checks.alice, page)
        links = [unescape(link) for link in re.findall(r'href="([^"]+)"', response.text)]
        links = [link for link in links if urlsplit(link).path == "/download"]
        identifiers = {parse_qs(urlsplit(link).query)["file"][0] for link in links}
        checks.record("catalog_" + page, response.status_code == 200 and identifiers == set(expected),
                      "Every shipped document is linked by the interface")
        for link in links:
            query = parse_qs(urlsplit(link).query)
            identifier = query["file"][0]
            response = checks.get(checks.alice, link)
            disposition = "attachment;" if query.get("attachment") == ["1"] else "inline;"
            checks.record("link_" + link, response.status_code == 200 and response.content == expected[identifier]
                          and response.headers.get("Content-Disposition", "").startswith(disposition),
                          "Exact document bytes and expected inline/attachment header", status=response.status_code)
    response = checks.get(checks.alice, "/download")
    checks.record("default_document", response.status_code == 200 and response.content == expected["onboarding.txt"],
                  "Existing default document preserved")
    bad_ids = ("", "unknown.txt", "./onboarding.txt", "../documents/onboarding.txt", "../lab-only.txt",
               "..\\lab-only.txt", "/srv/portal/documents/onboarding.txt", "/etc/passwd",
               "C:\\Windows\\win.ini", "//localhost/share/onboarding.txt", "onboarding.txt\x00")
    for identifier in bad_ids:
        for attachment in ("0", "1"):
            response = checks.get(checks.alice, "/download", params={"file": identifier, "attachment": attachment})
            checks.record("reject_id", response.status_code == 400 and "LAB_TRAVERSAL_PROOF" not in response.text,
                          "Unknown IDs and paths are rejected", identifier=identifier,
                          attachment=attachment, status=response.status_code)
    return checks.results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8082")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report)
    if report.exists():
        parser.error("Choose a new report path; previous evidence must not be overwritten")
    results = run(args.base)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(dict(base=args.base, results=results), ensure_ascii=False, indent=2), encoding="utf-8")
    sys.exit(0 if all(row["passed"] for row in results) else 1)
