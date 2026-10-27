"""Bounded demonstration against this lab only; no arbitrary target or wordlist."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

import requests

PASSWORDS = ['AutumnOffice01', 'AutumnOffice02', 'AutumnOffice03', 'AutumnOffice04',
             'AutumnOffice05', 'AutumnOffice06', 'AutumnOffice07', 'AutumnOffice08',
             'AutumnOffice09', 'Alice-Lab-2026!']
BASES = {'vulnerable': 'http://127.0.0.1:8080', 'waf': 'http://127.0.0.1:8081', 'fixed': 'http://127.0.0.1:8082'}
COMPOSE_BASES = {'vulnerable': 'http://vulnerable:5000', 'waf': 'http://waf:8080', 'fixed': 'http://fixed:5000'}


def attempt(base, password, number):
    # New cookie jar each time. Forged forwarding headers deliberately change.
    with requests.Session() as client:
        client.trust_env = False
        client.headers.update({'X-Forwarded-For': f'198.51.100.{number}', 'X-Real-IP': f'198.51.100.{number}'})
        page = client.get(base + '/login', timeout=12)
        page.raise_for_status()
        csrf = re.search(r'name="csrf_token" value="([a-f0-9]+)"', page.text)
        if not csrf:
            raise AssertionError('Missing login CSRF token')
        response = client.post(base + '/login', data={'username': 'alice', 'password': password,
                               'csrf_token': csrf.group(1)}, allow_redirects=False, timeout=12)
        me = client.get(base + '/api/me', allow_redirects=False, timeout=12)
        tickets = client.get(base + '/tickets', allow_redirects=False, timeout=12)
        identity = me.json() if me.status_code == 200 else None
        authenticated = (identity is not None and identity.get('id') == 1 and identity.get('username') == 'alice'
                         and tickets.status_code == 200 and 'Подключить второй монитор' in tickets.text)
        return {'attempt': number, 'status': response.status_code, 'authenticated': authenticated,
                'identity': identity, 'protected_status': tickets.status_code,
                'retry_after': response.headers.get('Retry-After'), 'fresh_session': True, 'forged_forwarding_headers': True}


def run(mode, base):
    rows = []
    for number, password in enumerate(PASSWORDS, 1):
        row = attempt(base, password, number)
        rows.append(row)
        print(f"{mode}: attempt {number:02d}/10 HTTP {row['status']} "
              f"{'AUTHENTICATED alice' if row['authenticated'] else 'NOT AUTHENTICATED'}", flush=True)
    report = {'mode': mode, 'base': base, 'attempts': rows, 'checks': {}}
    checks = report['checks']
    checks['wrong_passwords_never_authenticate'] = not any(r['authenticated'] for r in rows[:-1])
    if mode == 'vulnerable':
        checks['no_throttle'] = all(r['status'] == 200 for r in rows[:-1]) and rows[-1]['status'] == 302
        checks['last_password_authenticates_correct_user'] = rows[-1]['authenticated']
    else:
        checks['429_before_correct_password'] = any(r['status'] == 429 for r in rows[:-1])
        checks['no_success_during_burst'] = not any(r['authenticated'] for r in rows)
        fresh = attempt(base, PASSWORDS[-1], 11)
        report['fresh_session_during_limit'] = fresh
        checks['new_session_and_forged_xff_do_not_bypass'] = fresh['status'] == 429 and not fresh['authenticated']
        if mode == 'fixed':
            checks['retry_after_present'] = fresh['retry_after'] is not None and fresh['retry_after'].isdigit() and int(fresh['retry_after']) > 0
        if mode == 'fixed':
            cooldown = int(fresh['retry_after'] or 15)
            time.sleep(cooldown + 1)
            recovered = attempt(base, PASSWORDS[-1], 12)
            report['after_cooldown'] = recovered
            checks['correct_password_after_expiry'] = recovered['status'] == 302 and recovered['authenticated']
        else:
            cooldown = max(90, int(fresh['retry_after'] or 0))
            print(f'{mode}: waiting {cooldown + 1}s for recovery', flush=True)
            time.sleep(cooldown + 1)
            recovered = attempt(base, PASSWORDS[-1], 12)
            report['after_cooldown'] = recovered
            checks['correct_password_after_expiry'] = recovered['status'] == 302 and recovered['authenticated']
    report['passed'] = all(checks.values())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['all', *BASES], default='all')
    parser.add_argument('--inside-compose', action='store_true')
    parser.add_argument('--report-dir', type=Path)
    args = parser.parse_args()
    bases = COMPOSE_BASES if args.inside_compose else BASES
    output = args.report_dir or (Path('/reports') if args.inside_compose else Path(__file__).resolve().parents[1] / 'reports/generated')
    output.mkdir(parents=True, exist_ok=True)
    reports = []
    for mode in bases if args.mode == 'all' else [args.mode]:
        try:
            report = run(mode, bases[mode])
        except Exception as error:
            report = {'mode': mode, 'passed': False, 'error': f'{type(error).__name__}: {error}'}
        reports.append(report)
        (output / f'bruteforce-{mode}.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"{'PASS' if report['passed'] else 'FAIL'} {mode}: {report.get('checks', report.get('error'))}", flush=True)
    success = all(r['passed'] for r in reports)
    (output / 'bruteforce-summary.json').write_text(json.dumps({'utc': datetime.now(timezone.utc).isoformat(),
        'passed': success, 'results': reports}, ensure_ascii=False, indent=2), encoding='utf-8')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
