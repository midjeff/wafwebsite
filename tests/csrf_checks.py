"""Direct CSRF checks against the fixed Flask app, without the WAF."""
import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_fixed_app():
    name = "csrf_fixed_portal"
    package_dir = ROOT / "app-fixed"
    spec = importlib.util.spec_from_file_location(
        name, package_dir / "__init__.py", submodule_search_locations=[str(package_dir)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return __import__(name + ".main", fromlist=["create_app"])


def token(response):
    match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', response.get_data(as_text=True))
    if not match:
        raise AssertionError("CSRF token missing from rendered form")
    return match.group(1)


def main():
    (ROOT / ".runtime").mkdir(exist_ok=True)
    outcomes = []
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime") as temp:
        module = load_fixed_app()
        app = module.create_app({
            "TESTING": True,
            "DATABASE": str(Path(temp) / "csrf-test.db"),
            "SECRET_KEY": "isolated-csrf-check-key",
        })

        anon_a, anon_b = app.test_client(), app.test_client()
        token_a = token(anon_a.get("/login"))
        token_b = token(anon_b.get("/login"))
        assert token_a != token_b

        login_data = {"username": "alice", "password": "Alice-Lab-2026!"}
        for name, supplied in (("missing", None), ("invalid", "not-a-valid-token"), ("foreign-session", token_b)):
            data = dict(login_data)
            if supplied is not None:
                data["csrf_token"] = supplied
            response = anon_a.post("/login", data=data)
            assert response.status_code == 400, (name, response.status_code)
            outcomes.append({"route": "POST /login", "case": name, "status": response.status_code, "result": "PASS"})

        accepted = anon_a.post("/login", data={**login_data, "csrf_token": token_a})
        assert accepted.status_code == 302, accepted.status_code
        assert anon_a.get("/api/me").json["username"] == "alice"
        outcomes.append({"route": "POST /login", "case": "own-session-valid", "status": accepted.status_code, "result": "PASS"})

        alice, bob = app.test_client(), app.test_client()
        for client, password in ((alice, "Alice-Lab-2026!"), (bob, "Bob-Lab-2026!")):
            form_token = token(client.get("/login"))
            response = client.post("/login", data={"username": "alice" if client is alice else "bob", "password": password, "csrf_token": form_token})
            assert response.status_code == 302

        routes = {
            "POST /logout": ("/logout", "/", {}),
            "POST /tickets/new": ("/tickets/new", "/tickets/new", {"title": "CSRF ticket", "body": "isolated test", "category": "Сеть", "priority": "Обычный"}),
            "POST /tickets/<id>": ("/tickets/1001", "/tickets/1001", {"body": "CSRF comment"}),
            "POST /diagnostics": ("/diagnostics", "/diagnostics", {"host": "127.0.0.1"}),
        }
        for route, (path, form_path, payload) in routes.items():
            alice_own_token = token(alice.get(form_path))
            bob_foreign_token = token(bob.get(form_path))
            assert alice_own_token != bob_foreign_token
            for case, supplied in (("missing", None), ("invalid", "not-a-valid-token"), ("foreign-session", bob_foreign_token)):
                data = dict(payload)
                if supplied is not None:
                    data["csrf_token"] = supplied
                response = alice.post(path, data=data)
                assert response.status_code == 400, (route, case, response.status_code)
                outcomes.append({"route": route, "case": case, "status": response.status_code, "result": "PASS"})

        # A legitimate same-session write is accepted; it only touches the throwaway DB.
        ticket_token = token(alice.get("/tickets/new"))
        response = alice.post("/tickets/new", data={
            "csrf_token": ticket_token,
            "title": "CSRF_VALID_TOKEN_ACCEPTED",
            "body": "isolated test record",
            "category": "Сеть",
            "priority": "Обычный",
        })
        assert response.status_code == 302, response.status_code
        outcomes.append({"route": "POST /tickets/new", "case": "own-session-valid", "status": response.status_code, "result": "PASS"})

    result = {
        "test": "fixed-app-direct-csrf",
        "waf": False,
        "database": "temporary isolated SQLite database",
        "checks": outcomes,
        "passed": len(outcomes),
        "failed": 0,
    }
    output = ROOT / "reports" / "generated" / "csrf-checks.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(outcomes)}/{len(outcomes)} direct fixed-app CSRF checks; WAF bypassed")


if __name__ == "__main__":
    main()
