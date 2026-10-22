"""Real Flask/SQLite and OS-process checks, no WAF simulation."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_package(name, directory):
    spec = importlib.util.spec_from_file_location(name, directory / "__init__.py", submodule_search_locations=[str(directory)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return __import__(name + ".main", fromlist=["create_app"])


def token(response):
    match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', response.get_data(as_text=True))
    if not match:
        raise AssertionError("CSRF token missing")
    return match.group(1)


class PortalChecks:
    fixed = False

    def setUp(self):
        (ROOT / ".runtime").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".runtime")
        self.module = load_package("fixed_portal" if self.fixed else "vuln_portal", ROOT / ("app-fixed" if self.fixed else "app"))
        self.app = self.module.create_app({"TESTING": True, "DATABASE": str(Path(self.temp.name) / "test.db"), "SECRET_KEY": "isolated-test-key"})
        self.alice = self.app.test_client()
        self.bob = self.app.test_client()
        self.login(self.alice, "alice", "Alice-Lab-2026!")
        self.login(self.bob, "bob", "Bob-Lab-2026!")

    def tearDown(self):
        self.temp.cleanup()

    def login(self, client, username, password):
        result = client.post("/login", data={"csrf_token": token(client.get("/login")), "username": username, "password": password}, follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        self.assertIn("Мои заявки", result.get_data(as_text=True))

    def post(self, client, path, data):
        return client.post(path, data={**data, "csrf_token": token(client.get(path))}, follow_redirects=True)

    def test_normal_pages_and_documents(self):
        for path in ("/", "/tickets", "/tickets/1001", "/tickets/new", "/employees", "/greeting", "/documents", "/diagnostics", "/lab"):
            with self.subTest(path=path):
                self.assertEqual(self.alice.get(path).status_code, 200)
        document = self.alice.get("/download?file=onboarding.txt")
        self.assertIn("Первый день", document.get_data(as_text=True))
        document.close()
        download = self.alice.get("/download?file=vpn.txt&attachment=1")
        self.assertIn("attachment", download.headers["Content-Disposition"])
        download.close()

    def test_create_and_persist(self):
        created = self.post(self.alice, "/tickets/new", {"title": "UNIT_CREATED", "body": "Сохраняется после нового подключения", "category": "Сеть", "priority": "Обычный"})
        self.assertIn("UNIT_CREATED", created.get_data(as_text=True))
        other_app = self.module.create_app({"TESTING": True, "DATABASE": self.app.config["DATABASE"], "SECRET_KEY": "isolated-test-key"})
        client = other_app.test_client()
        self.login(client, "alice", "Alice-Lab-2026!")
        self.assertIn("UNIT_CREATED", client.get("/tickets").get_data(as_text=True))

    def test_normal_comments_two_sessions(self):
        self.post(self.alice, "/tickets/1003", {"body": "NORMAL_SHARED_COMMENT"})
        self.assertIn("NORMAL_SHARED_COMMENT", self.bob.get("/tickets/1003").get_data(as_text=True))

    def test_sqli(self):
        normal = self.alice.get("/employees", query_string={"q": "Алиса"}).get_data(as_text=True)
        attack = self.alice.get("/employees", query_string={"q": "' OR 1=1 -- "}).get_data(as_text=True)
        self.assertEqual(normal.count('data-person-id='), 1)
        self.assertEqual(attack.count('data-person-id='), 0 if self.fixed else 4)

    def test_reflected_xss_markup(self):
        payload = '<script>alert("LAB_XSS")</script>'
        response = self.alice.get("/greeting", query_string={"name": payload})
        html = response.get_data(as_text=True)
        self.assertEqual(payload in html, not self.fixed)
        if self.fixed:
            self.assertIn("&lt;script&gt;", html)

    def test_stored_xss_markup(self):
        payload = '<script>alert("LAB_STORED")</script>'
        self.post(self.alice, "/tickets/1003", {"body": payload})
        html = self.bob.get("/tickets/1003").get_data(as_text=True)
        self.assertEqual(payload in html, not self.fixed)
        if self.fixed:
            self.assertIn("&lt;script&gt;", html)
        # Actual cleanup, independent of WAF request blocking.
        result = self.app.test_cli_runner().invoke(args=["clean-comments"])
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("LAB_STORED", self.bob.get("/tickets/1003").get_data(as_text=True))

    def test_command_injection_real_process(self):
        separator = " & " if os.name == "nt" else "; "
        result = self.post(self.alice, "/diagnostics", {"host": "127.0.0.1" + separator + "echo LAB_TEST"})
        if self.fixed:
            self.assertEqual(result.status_code, 400)
            self.assertNotIn('id="diagnostic-output"', result.get_data(as_text=True))
        else:
            html = result.get_data(as_text=True)
            output = re.search(r'<pre id="diagnostic-output">(.*?)</pre>', html, re.S).group(1)
            self.assertIn("LAB_TEST", output)

    def test_normal_diagnostics(self):
        result = self.post(self.alice, "/diagnostics", {"host": "127.0.0.1"})
        self.assertEqual(result.status_code, 200)
        self.assertIn("127.0.0.1", result.get_data(as_text=True).split('id="diagnostic-output">')[1])

    def test_path_traversal(self):
        response = self.alice.get("/download", query_string={"file": "../lab-only.txt"})
        self.assertEqual(response.status_code, 400 if self.fixed else 200)
        self.assertEqual("LAB_TRAVERSAL_PROOF" in response.get_data(as_text=True), not self.fixed)
        response.close()

    def test_idor_and_post_authorization(self):
        self.assertIn("BOB_PRIVATE", self.bob.get("/tickets/1002").get_data(as_text=True))
        attack = self.alice.get("/tickets/1002")
        self.assertEqual(attack.status_code, 403 if self.fixed else 200)
        self.assertEqual("BOB_PRIVATE" in attack.get_data(as_text=True), not self.fixed)
        result = self.alice.post("/tickets/1002", data={"csrf_token": token(self.alice.get("/tickets/1001")), "body": "UNAUTHORIZED_WRITE"})
        self.assertEqual(result.status_code, 403 if self.fixed else 302)
        self.assertEqual("UNAUTHORIZED_WRITE" in self.bob.get("/tickets/1002").get_data(as_text=True), not self.fixed)

    def test_authentication_csrf_and_validation(self):
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/tickets/1002?user_id=2").status_code, 302)
        bad = anonymous.post("/login", data={"csrf_token": token(anonymous.get("/login")), "username": "alice", "password": "wrong"})
        self.assertIn("Неверный логин", bad.get_data(as_text=True))
        self.assertEqual(self.alice.post("/tickets/1003", data={"body": "NO_CSRF"}).status_code, 400)
        self.assertEqual(self.post(self.alice, "/tickets/new", {"title": "", "body": ""}).status_code, 400)

    def test_lab_page_has_no_active_payload(self):
        html = self.alice.get("/lab").get_data(as_text=True)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


class VulnerableTests(PortalChecks, unittest.TestCase):
    pass


class FixedTests(PortalChecks, unittest.TestCase):
    fixed = True

    def test_path_containment_and_sql_alternates(self):
        for path in (str(ROOT / "app-fixed" / "lab-only.txt"), "../../app-fixed/lab-only.txt"):
            self.assertEqual(self.alice.get("/download", query_string={"file": path}).status_code, 400)
        for payload in ("' OR 'a'='a", "' UNION SELECT 1,2,3,4,5 -- "):
            response = self.alice.get("/employees", query_string={"q": payload})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('data-person-id=', response.get_data(as_text=True))
        for host in ("8.8.8.8", "127.0.0.1; echo OTHER", "--help", "localhost"):
            self.assertEqual(self.post(self.alice, "/diagnostics", {"host": host}).status_code, 400)


class ProcessTests(unittest.TestCase):
    def test_timeout_and_output_limit(self):
        from app.process import bounded_run
        start = time.monotonic()
        result = bounded_run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.3)
        self.assertLess(time.monotonic() - start, 4)
        self.assertIn("Превышено время", result)
        result = bounded_run([sys.executable, "-c", "print('x'*100000)"], limit=1024)
        self.assertLess(len(result), 1200)
        self.assertIn("Вывод ограничен", result)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"suite": "Flask test client + real local OS processes", "platform": sys.platform,
              "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "success": result.wasSuccessful(),
              "limits": "No Docker/WAF/SonarQube; XSS tests inspect HTML, not JavaScript execution. Windows command injection uses &."}
    destination = ROOT / "reports" / "generated" / "local-checks.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("PASS" if result.wasSuccessful() else "FAIL", json.dumps(report))
    sys.exit(0 if result.wasSuccessful() else 1)
