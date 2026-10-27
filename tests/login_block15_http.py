"""Real fixed-only HTTP check; changes login state, never portal records."""
import argparse
import json
from pathlib import Path
import re
import time

import requests


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    destination = Path(args.report)
    if destination.exists():
        parser.error('Choose a new report filename')
    rows = []

    def attempt(password):
        with requests.Session() as client:
            client.trust_env = False
            form = client.get('http://127.0.0.1:8082/login', timeout=10)
            form.raise_for_status()
            csrf = re.search(r'name="csrf_token" value="([^"]+)"', form.text).group(1)
            response = client.post('http://127.0.0.1:8082/login', timeout=10,
                                   data={'username': 'alice', 'password': password, 'csrf_token': csrf},
                                   allow_redirects=False)
            row = {'status': response.status_code, 'retry_after': response.headers.get('Retry-After')}
            if response.status_code == 302:
                me = client.get('http://127.0.0.1:8082/api/me', timeout=10)
                row['authenticated'] = me.status_code == 200 and me.json().get('username') == 'alice'
            rows.append(row)
            return row

    try:
        initial = attempt('Alice-Lab-2026!')
        if initial['status'] == 429:
            assert 1 <= int(initial['retry_after']) <= 15
            time.sleep(int(initial['retry_after']) + 1)
            initial = attempt('Alice-Lab-2026!')
        assert initial.get('authenticated'), 'Initial login failed'
        for _ in range(3):
            assert attempt('Wrong-local-test!')['status'] == 200
        fourth = attempt('Alice-Lab-2026!')
        assert fourth['status'] == 429
        assert 1 <= int(fourth['retry_after']) <= 15
        time.sleep(2)
        later = attempt('Alice-Lab-2026!')
        assert later['status'] == 429
        assert 0 < int(later['retry_after']) < int(fourth['retry_after'])
        time.sleep(int(later['retry_after']) + 1)
        assert attempt('Alice-Lab-2026!').get('authenticated')
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({'base': 'http://127.0.0.1:8082', 'rows': rows}, indent=2), encoding='utf-8')
    print('PASS: 3 failures; fourth correct password 429; Retry-After decreases; login succeeds after expiry')


if __name__ == '__main__':
    run()
