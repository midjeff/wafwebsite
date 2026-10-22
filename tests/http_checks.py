"""HTTP regression checks against real services. No fabricated WAF results."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
import uuid

import requests

SQLI = "' OR 1=1 -- "
REFLECTED = '<script>alert("LAB_XSS")</script>'
STORED = '<script>alert("LAB_STORED")</script>'


class Checks:
    def __init__(self, base, mode, platform):
        self.base = base.rstrip("/")
        self.mode = mode
        self.platform = platform
        self.results = []
        self.alice = requests.Session()
        self.bob = requests.Session()
        # Environment proxy settings must not redirect local lab requests.
        self.alice.trust_env = self.bob.trust_env = False

    def record(self, name, condition, detail, **evidence):
        self.results.append(dict(name=name, passed=bool(condition), detail=detail, **evidence))
        print(f"{'PASS' if condition else 'FAIL'} [{self.mode}] {name}: {detail}", flush=True)

    def get(self, session, path, **kwargs):
        return session.get(self.base + path, timeout=12, **kwargs)

    def csrf(self, session, path):
        response = self.get(session, path)
        response.raise_for_status()
        match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', response.text)
        if not match:
            raise RuntimeError(f"No CSRF token at {path}")
        return match.group(1)

    def post(self, session, path, data, *, case_id=None, follow=True):
        csrf = self.csrf(session, path)
        return session.post(self.base + path, params={"lab_case": case_id} if case_id else None,
                            data={**data, "csrf_token": csrf}, timeout=12, allow_redirects=follow)

    def run(self):
        ready = False
        for _ in range(30):
            try:
                response = self.get(self.alice, "/health")
                ready = response.status_code == 200 and response.json().get("status") == "ok"
            except (requests.RequestException, ValueError):
                pass
            if ready:
                break
            time.sleep(2)
        if not ready:
            raise RuntimeError("Service did not become ready within 60 seconds")
        for client, username, password in ((self.alice, "alice", "Alice-Lab-2026!"), (self.bob, "bob", "Bob-Lab-2026!")):
            response = self.post(client, "/login", {"username": username, "password": password})
            self.record("login_" + username, response.status_code == 200 and "Мои заявки" in response.text, "Separate authenticated cookie jar")
        for path, content in (("/", "Последние заявки"), ("/tickets", "Подключить второй монитор"), ("/documents", "Первый день"), ("/lab", "Один портал")):
            response = self.get(self.alice, path)
            self.record("normal_" + path, response.status_code == 200 and content in response.text, "Page content verified")
        response = self.get(self.alice, "/employees", params={"q": "Алиса"})
        self.record("normal_search", response.status_code == 200 and response.text.count('data-person-id=') == 1, "Normal search returns exactly one employee")
        response = self.get(self.alice, "/download", params={"file": "onboarding.txt", "attachment": "1"})
        self.record("normal_download", "Первый день" in response.text and "attachment" in response.headers.get("Content-Disposition", ""), "Document content and attachment header")
        marker = "HTTP_NORMAL_" + uuid.uuid4().hex[:12]
        response = self.post(self.alice, "/tickets/new", {"title": marker, "body": "Проверка сохранения заявки", "category": "Сеть", "priority": "Обычный"})
        listed = self.get(self.alice, "/tickets")
        self.record("normal_create", response.status_code == 200 and marker in response.text and marker in listed.text, "Ticket saved and visible in a later GET")
        response = self.post(self.alice, "/tickets/1003", {"body": marker})
        self.record("normal_comment", response.status_code == 200 and marker in self.get(self.bob, "/tickets/1003").text, "Bob sees Alice's saved comment on shared ticket")
        response = self.post(self.alice, "/diagnostics", {"host": "127.0.0.1"})
        match = re.search(r'<pre id="diagnostic-output">(.*?)</pre>', response.text, re.S)
        received = ("1 received" in match.group(1) if self.platform == "linux" else "(0%" in match.group(1)) if match else False
        self.record("normal_ping", response.status_code == 200 and match and "127.0.0.1" in match.group(1) and received, f"{self.platform}: loopback ping receives a reply")

        case = uuid.uuid4().hex
        response = self.get(self.alice, "/employees", params={"q": SQLI, "lab_case": case})
        count = response.text.count('data-person-id=')
        self.attack("SQLi", response, case, count == 4, count == 0 and response.status_code == 200)
        case = uuid.uuid4().hex
        response = self.get(self.alice, "/greeting", params={"name": REFLECTED, "lab_case": case})
        self.attack("Reflected XSS", response, case, REFLECTED in response.text, "&lt;script&gt;" in response.text and REFLECTED not in response.text)

        clean = "LAB_STORED" not in self.get(self.bob, "/tickets/1003").text
        self.record("stored_clean_precondition", clean, "No old stored payload; run clean-comments before each mode")
        if clean:
            case = uuid.uuid4().hex
            response = self.post(self.alice, "/tickets/1003", {"body": STORED}, case_id=case, follow=False)
            saved = self.get(self.bob, "/tickets/1003")
            self.attack("Stored XSS", response, case, STORED in saved.text,
                        "&lt;script&gt;" in saved.text and STORED not in saved.text,
                        waf_extra="LAB_STORED" not in saved.text)

        case = uuid.uuid4().hex
        payload = "127.0.0.1; echo LAB_TEST" if self.platform == "linux" else "127.0.0.1 & echo LAB_TEST"
        response = self.post(self.alice, "/diagnostics", {"host": payload}, case_id=case, follow=False)
        output = re.search(r'<pre id="diagnostic-output">(.*?)</pre>', response.text, re.S)
        self.attack("Command Injection", response, case, output is not None and "LAB_TEST" in output.group(1), response.status_code == 400 and output is None)
        case = uuid.uuid4().hex
        # Query parameter encoding preserves ../; URL path normalization cannot remove it.
        response = self.get(self.alice, "/download", params={"file": "../lab-only.txt", "lab_case": case})
        self.attack("Path Traversal", response, case, "LAB_TRAVERSAL_PROOF" in response.text, response.status_code == 400 and "LAB_TRAVERSAL_PROOF" not in response.text)

        owner = self.get(self.bob, "/tickets/1002")
        response = self.get(self.alice, "/tickets/1002")
        expected = response.status_code == 403 and "BOB_PRIVATE" not in response.text if self.mode == "fixed" else response.status_code == 200 and "BOB_PRIVATE" in response.text
        self.record("IDOR", expected and "BOB_PRIVATE" in owner.text,
                    "Bob owns ticket; Alice denied" if self.mode == "fixed" else "Alice reads Bob's ticket; WAF does not enforce ownership", status=response.status_code)

    def attack(self, name, response, case_id, exploited, fixed, waf_extra=True):
        if self.mode == "waf":
            passed = response.status_code == 403 and waf_extra
            detail = "HTTP block observed; correlated audit evidence is checked separately"
        elif self.mode == "fixed":
            passed, detail = fixed, "Remediation behavior checked without WAF"
        else:
            passed, detail = exploited, "Exploitation effect observed in response or persisted data"
        self.record(name, passed, detail, status=response.status_code, case_id=case_id, attack=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["vulnerable", "waf", "fixed"])
    parser.add_argument("--base")
    parser.add_argument("--report-dir", default="/reports")
    parser.add_argument("--platform", choices=["linux", "windows"], default="linux")
    args = parser.parse_args()
    base = args.base or {"vulnerable": "http://vulnerable:5000", "waf": "http://waf:8080", "fixed": "http://fixed:5000"}[args.mode]
    checks = Checks(base, args.mode, args.platform)
    try:
        checks.run()
    except Exception as error:
        checks.record("technical_error", False, f"{type(error).__name__}: {error}")
    report = {"mode": args.mode, "base": base, "platform": args.platform, "results": checks.results,
              "xss_scope": "HTTP markup only; browser JavaScript execution requires the documented manual check"}
    directory = Path(args.report_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"http-{args.mode}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    sys.exit(0 if checks.results and all(row["passed"] for row in checks.results) else 1)
