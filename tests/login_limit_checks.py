"""Account lockout checks using production durations and controlled clocks."""
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from unit_checks import ROOT, load_package, token


def worker_login(database):
    m = load_package('race_fixed', ROOT / 'app-fixed')
    a = m.create_app({'TESTING': True, 'DATABASE': database, 'SECRET_KEY': 'test'})
    c = a.test_client()
    return c.post('/login', data={'username':'alice','password':'wrong','csrf_token':token(c.get('/login'))}).status_code


class LoginLimits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.runtime')
        self.m = load_package('policy_fixed', ROOT / 'app-fixed')
        self.config = {'TESTING':True,'DATABASE':str(Path(self.tmp.name)/'test.db'),'SECRET_KEY':'test'}
        self.a = self.m.create_app(self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def attempt(self, t, password='wrong', csrf=True, app=None):
        c = (app or self.a).test_client()
        data = {'username':'alice','password':password}
        with patch('policy_fixed.login_limits.time.time', return_value=t):
            if csrf: data['csrf_token'] = token(c.get('/login'))
            r = c.post('/login', data=data)
        return r

    def test_lock_and_expiry(self):
        for t in (1000,1001,1002): self.assertEqual(self.attempt(t).status_code,200)
        r = self.attempt(1002,'Alice-Lab-2026!')
        self.assertEqual(r.status_code,429)
        self.assertEqual(r.headers['Retry-After'],'15')
        self.assertEqual(self.attempt(1007).headers['Retry-After'],'10')
        self.assertEqual(self.attempt(1016).headers['Retry-After'],'1')
        self.assertEqual(self.attempt(1017,'Alice-Lab-2026!').status_code,302)

    def test_success_resets_consecutive_failures(self):
        self.attempt(1000); self.attempt(1001)
        self.assertEqual(self.attempt(1002,'Alice-Lab-2026!').status_code,302)
        self.assertEqual(self.attempt(1003).status_code,200)
        self.assertEqual(self.attempt(1004).status_code,200)
        self.assertEqual(self.attempt(1005,'Alice-Lab-2026!').status_code,302)

    def test_existing_long_block_is_shortened_once(self):
        old = self.m.create_app({**self.config, 'LOGIN_BLOCK_SECONDS': 900})
        for t in (1000, 1001, 1002): self.attempt(t, app=old)
        self.assertEqual(self.attempt(1003).headers['Retry-After'], '15')
        self.assertEqual(self.attempt(1008).headers['Retry-After'], '10')
        self.assertEqual(self.attempt(1018, 'Alice-Lab-2026!').status_code, 302)

    def test_csrf_does_not_count(self):
        for t in range(1000,1005): self.assertEqual(self.attempt(t,csrf=False).status_code,400)
        self.assertEqual(self.attempt(1006,'Alice-Lab-2026!').status_code,302)

    def test_rolling_window(self):
        for t in (1000,1500,1901,1902): self.assertEqual(self.attempt(t).status_code,200)
        self.assertEqual(self.attempt(1903,'Alice-Lab-2026!').status_code,429)

    def test_new_instance_and_sessions(self):
        for t in (1000,1001,1002): self.attempt(t)
        a = self.m.create_app(self.config)
        self.assertEqual(self.attempt(1003,'Alice-Lab-2026!',app=a).status_code,429)

    def test_database_failure_closed(self):
        import sqlite3
        with patch('policy_fixed.main.authenticate',side_effect=sqlite3.OperationalError('locked')):
            self.assertEqual(self.attempt(1000,'Alice-Lab-2026!').status_code,503)

    def test_process_race(self):
        with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('spawn')) as pool:
            statuses=list(pool.map(worker_login,[self.config['DATABASE']]*12))
        self.assertEqual(statuses.count(200),3)
        self.assertEqual(statuses.count(429),9)

if __name__ == '__main__': unittest.main(verbosity=2)
