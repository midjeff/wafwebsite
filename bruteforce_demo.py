#!/usr/bin/env python3
"""Bounded local NEXUS login demonstration. Python standard library only.

CLI targets are fixed to localhost:8080/8081/8082. Each burst makes at most
10 login POSTs, stops on a successful protected-page check or HTTP 429,
and uses a separate cookie jar. No arbitrary target or password list input.
"""
import argparse
import http.cookiejar
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

TARGETS = {"vulnerable": 8080, "waf": 8081, "fixed": 8082}
ACCOUNTS = {"alice": "Alice-Lab-2026!", "bob": "Bob-Lab-2026!"}


class LoginForms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"attrs": attrs, "inputs": []}
        elif tag == "input" and self.current is not None:
            self.current["inputs"].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


class LocalRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, base):
        self.origin = urllib.parse.urlsplit(base)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme, target.hostname, target.port) != (
            self.origin.scheme, self.origin.hostname, self.origin.port
        ):
            raise RuntimeError("Refusing a redirect outside the selected local origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(opener, url, data=None):
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": "NEXUS-Local-Demo/1.0", "Accept": "text/html"},
    )
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return (response.code, response.geturl(), response.headers,
                response.read().decode("utf-8", errors="replace"))


def login_payload(base, html, user, password):
    parser = LoginForms()
    parser.feed(html)
    forms = [f for f in parser.forms if any(
        item.get("type", "text").lower() == "password" for item in f["inputs"]
    )]
    if len(forms) != 1:
        raise RuntimeError("Expected exactly one login form with a password field")
    form = forms[0]
    if form["attrs"].get("method", "get").lower() != "post":
        raise RuntimeError("Login form is not POST; inspect the actual form")
    inputs = form["inputs"]
    password_names = [i["name"] for i in inputs
                      if i.get("type", "text").lower() == "password" and i.get("name")]
    candidates = [i for i in inputs if i.get("name") and
                  i.get("type", "text").lower() in ("text", "email")]
    preferred = [i for i in candidates if i["name"].lower() in
                 ("username", "user", "login", "email")]
    candidates = preferred or candidates
    if len(password_names) != 1 or len(candidates) != 1:
        raise RuntimeError("Cannot uniquely identify the login/password inputs")
    fields = {i["name"]: i.get("value", "") for i in inputs
              if i.get("type", "text").lower() == "hidden" and i.get("name")}
    fields[candidates[0]["name"]] = user
    fields[password_names[0]] = password
    action = urllib.parse.urljoin(base + "/login", form["attrs"].get("action") or "/login")
    original, target = urllib.parse.urlsplit(base), urllib.parse.urlsplit(action)
    if (target.scheme, target.hostname, target.port) != (
        original.scheme, original.hostname, original.port
    ):
        raise RuntimeError("Refusing a form submission outside the local origin")
    return action, urllib.parse.urlencode(fields).encode("utf-8")


def demonstrate(base, user, correct, check=False):
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), LocalRedirects(base)
    )
    passwords = [correct] if check else [
        "123456",
        "password",
        "admin123",
        "qwerty",
        "12345678",
        "welcome",
        "alice123",
        "password123",
        "letmein",
        correct,
    ]
    print("Target:", base, "| Account:", user)
    print("Mode:", "one correct-password check" if check else "9 wrong passwords + correct password last")
    for number, password in enumerate(passwords, 1):
        code, _, headers, html = fetch(opener, base + "/login")
        if code == 429:
            print("%02d GET /login -> HTTP 429 BLOCKED" % number)
            print("Retry-After:", headers.get("Retry-After", "not supplied; use the project cooldown"))
            return "blocked"
        if code != 200:
            raise RuntimeError("Cannot load login form: HTTP %s" % code)
        action, payload = login_payload(base, html, user, password)
        code, _, headers, _ = fetch(opener, action, payload)
        if code == 429:
            print("%02d POST /login -> HTTP 429 BLOCKED" % number)
            print("Retry-After:", headers.get("Retry-After", "not supplied; use the project cooldown"))
            return "blocked"
        if code in (400, 403):
            raise RuntimeError("Login returned HTTP %s; check CSRF/WAF logs, not a proven rate limit" % code)
        if code >= 500:
            raise RuntimeError("Server error HTTP %s" % code)
        protected, final_url, _, _ = fetch(opener, base + "/employees")
        path = urllib.parse.urlsplit(final_url).path.rstrip("/")
        authenticated = protected == 200 and path == "/employees"
        print("%02d login HTTP %s | protected /employees: %s" % (
            number, code, "ACCESS GRANTED" if authenticated else "NO ACCESS"
        ))
        if authenticated:
            if password != correct:
                raise RuntimeError("An intentionally wrong password granted access; investigate")
            print("SUCCESS: correct password verified using a protected page")
            return "success"
        if password == correct:
            raise RuntimeError("Known correct password did not grant access and no HTTP 429 was observed")
    return "no_success"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("--user", choices=ACCOUNTS, default="alice")
    parser.add_argument("--check", action="store_true", help="Only one correct-password login, e.g. after cooldown")
    args = parser.parse_args()
    base = "http://localhost:%s" % TARGETS[args.target]
    try:
        result = demonstrate(base, args.user, ACCOUNTS[args.user], args.check)
    except (RuntimeError, OSError, urllib.error.URLError) as exc:
        print("CHECK FAILED:", exc, file=sys.stderr)
        return 2
    expected = "success" if args.check or args.target == "vulnerable" else "blocked"
    if result != expected:
        print("UNEXPECTED: expected %s, observed %s" % (expected, result), file=sys.stderr)
        return 2
    print("EXPECTED RESULT:", result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
