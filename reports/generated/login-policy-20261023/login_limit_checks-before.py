"""SQLite/Flask login limits: persistence, spoofing, expiry and process races."""
from concurrent.futures import ProcessPoolExecutor
import json
import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from unit_checks import ROOT, load_package, token


def worker_login(arguments):
    database, username, source = arguments
    module = load_package('parallel_fixed', ROOT / 'app-fixed')
    app = module.create_app({'TESTING': True, 'DATABASE': database, 'SECRET_KEY': 'concurrency-test',
                             'LOGIN_MAX_FAILURES': 5, 'LOGIN_WINDOW_SECONDS': 120, 'LOGIN_BLOCK_SECONDS': 60})
    with app.test_client() as client:
        csrf = token(client.get('/login'))
        response = client.post('/login', data={'username': username, 'password': 'IncorrectPass123', 'csrf_token': csrf},
                               environ_overrides={'REMOTE_ADDR': source})
        return response.status_code


class LoginLimits(unittest.TestCase):
    def setUp(self):
        (ROOT / '.runtime').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.runtime')
        self.module = load_package('limit_fixed', ROOT / 'app-fixed')
        self.config = {'TESTING': True, 'DATABASE': str(Path(self.temp.name) / 'limits.db'), 'SECRET_KEY': 'unit-limits',
                       'LOGIN_MAX_FAILURES': 3, 'LOGIN_WINDOW_SECONDS': 30, 'LOGIN_BLOCK_SECONDS': 10}
        self.app = self.module.create_app(self.config)

    def tearDown(self):
        self.temp.cleanup()

    def attempt(self, username='alice', password='wrong', source='192.0.2.1', app=None, forwarded='203.0.113.1'):
        client = (app or self.app).test_client()
        csrf = token(client.get('/login'))
        response = client.post('/login', data={'username': username, 'password': password, 'csrf_token': csrf},
                               headers={'X-Forwarded-For': forwarded, 'X-Real-IP': forwarded},
                               environ_overrides={'REMOTE_ADDR': source})
        return response, client

    def test_new_sessions_spoofed_headers_and_expiry(self):
        with patch('limit_fixed.login_limits.time.time', return_value=1000):
            for i in range(3):
                r, _ = self.attempt(forwarded=f'203.0.113.{i + 1}')
                self.assertEqual(r.status_code, 429 if i == 2 else 200)
            r, c = self.attempt(password='Alice-Lab-2026!')
            self.assertEqual(r.status_code, 429)
            self.assertEqual(r.headers['Retry-After'], '10')
            self.assertEqual(c.get('/api/me').status_code, 302)
        with patch('limit_fixed.login_limits.time.time', return_value=1011):
            r, c = self.attempt(password='Alice-Lab-2026!')
            self.assertEqual(r.status_code, 302)
            self.assertEqual(c.get('/api/me').json['username'], 'alice')

    def test_known_and_unknown_same_response_sequence(self):
        with patch('limit_fixed.login_limits.time.time', return_value=1000):
            for _ in range(4):
                known, _ = self.attempt(source='192.0.2.1')
                unknown, _ = self.attempt(username='missing-account', source='192.0.2.2')
                self.assertEqual(known.status_code, unknown.status_code)
                self.assertEqual(known.headers.get('Retry-After'), unknown.headers.get('Retry-After'))
                # CSRF values differ; messages/statuses must not disclose account existence.
                for message in ('Неверный логин или пароль', 'Слишком много попыток входа'):
                    self.assertEqual(message in known.text, message in unknown.text)

    def test_account_budget_survives_source_changes(self):
        for i in range(3):
            r, _ = self.attempt(source=f'192.0.2.{i + 1}')
        self.assertEqual(r.status_code, 429)
        r, _ = self.attempt(password='Alice-Lab-2026!', source='192.0.2.99')
        self.assertEqual(r.status_code, 429)

    def test_source_budget_survives_account_changes_and_success(self):
        self.attempt(username='missing1')
        r, _ = self.attempt(username='bob', password='Bob-Lab-2026!')
        self.assertEqual(r.status_code, 302)
        self.attempt(username='missing2')
        r, _ = self.attempt(username='missing3')
        self.assertEqual(r.status_code, 429)
        r, _ = self.attempt(password='Alice-Lab-2026!')
        self.assertEqual(r.status_code, 429)

    def test_budget_persists_new_app_and_cli_reset(self):
        for _ in range(3):
            self.attempt()
        second = self.module.create_app(self.config)
        self.assertEqual(self.attempt(app=second)[0].status_code, 429)
        result = second.test_cli_runner().invoke(args=['reset-login-limits'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(self.attempt(app=second, password='Alice-Lab-2026!')[0].status_code, 302)
        self.assertEqual(second.test_client().post('/reset-login-limits').status_code, 400)
        self.assertEqual(second.test_client().get('/reset-login-limits').status_code, 404)

    def test_window_expiration_and_success_clear_account(self):
        with patch('limit_fixed.login_limits.time.time', return_value=1000):
            self.attempt()
            self.attempt()
        with patch('limit_fixed.login_limits.time.time', return_value=1031):
            self.assertEqual(self.attempt()[0].status_code, 200)
            self.assertEqual(self.attempt(password='Alice-Lab-2026!')[0].status_code, 302)
            # New source avoids its independent budget; successful login cleared the account.
            self.assertEqual(self.attempt(source='192.0.2.2')[0].status_code, 200)
            self.assertEqual(self.attempt(source='192.0.2.2')[0].status_code, 200)

    def test_database_failure_fails_closed(self):
        import sqlite3
        with patch('limit_fixed.main.authenticate', side_effect=sqlite3.OperationalError('database is locked')):
            r, client = self.attempt(password='Alice-Lab-2026!')
            self.assertEqual(r.status_code, 503)
            self.assertEqual(client.get('/api/me').status_code, 302)

    def test_multiple_processes_cannot_overrun_account_limit(self):
        tasks = [(self.config['DATABASE'], 'alice', f'192.0.2.{i + 1}') for i in range(12)]
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('spawn')) as executor:
            statuses = list(executor.map(worker_login, tasks))
        self.assertEqual(statuses.count(200), 4)
        self.assertEqual(statuses.count(429), 8)

    def test_multiple_processes_cannot_overrun_source_limit(self):
        tasks = [(self.config['DATABASE'], f'missing-{i}', '192.0.2.1') for i in range(12)]
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('spawn')) as executor:
            statuses = list(executor.map(worker_login, tasks))
        self.assertEqual(statuses.count(200), 4)
        self.assertEqual(statuses.count(429), 8)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LoginLimits))
    report = {'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'success': result.wasSuccessful(), 'platform': sys.platform,
              'concurrency': '4 spawned OS processes, 12 concurrent requests for each independent budget'}
    (ROOT / 'reports/generated/login-limit-checks.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    sys.exit(0 if result.wasSuccessful() else 1)
