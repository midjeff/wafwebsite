"""Confirm 429 enforcement comes from nginx limit_req, not a CRS rule."""
import argparse
import json
from pathlib import Path
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--log', default='/logs/login-rate.log')
parser.add_argument('--report', default='/reports/bruteforce-waf.json')
parser.add_argument('--output', default='/reports/nginx-login-evidence.json')
args = parser.parse_args()
report = json.loads(Path(args.report).read_text(encoding='utf-8'))
log = Path(args.log).read_text(encoding='utf-8-sig', errors='replace')
lines = re.findall(r'(?m)^LOGIN_LIMIT .*uri=/login status=429 limit=REJECTED\s*$', log)
expected = sum(row['status'] == 429 for row in report['attempts']) + int(report['fresh_session_during_limit']['status'] == 429)
passed = report['passed'] and expected > 0 and len(lines) >= expected and 'by zone "portal_login"' in log
evidence = {'passed': bool(passed), 'expected_429': expected, 'nginx_rejected_records': len(lines),
            'mechanism': 'nginx limit_req, portal_login shared-memory zone; not ModSecurity/CRS', 'records': lines}
Path(args.output).write_text(json.dumps(evidence, indent=2), encoding='utf-8')
print(('PASS' if passed else 'FAIL') + f' nginx limit_req audit: {len(lines)} rejected records, expected at least {expected}')
sys.exit(0 if passed else 1)
