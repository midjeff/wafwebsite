"""Initialize only a new local SonarQube; never print credentials or tokens."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import sys

import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:9000'
PRIVATE = ROOT / '.runtime'


def private_write(path, value):
    # .runtime/ is excluded from Git. On POSIX the owner alone can read the file.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w', encoding='utf-8') as stream:
        stream.write(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize-default-admin', action='store_true',
                        help='Explicitly allow changing a fresh admin/admin password and creating a local token')
    args = parser.parse_args()
    client = requests.Session()
    client.trust_env = False

    def api(path, data=None):
        result = (client.post(BASE + path, data=data, timeout=30) if data is not None
                  else client.get(BASE + path, timeout=30))
        if not result.ok:
            # Do not dump response bodies, request headers or credentials.
            raise RuntimeError(f'SonarQube {path.split("?")[0]} returned HTTP {result.status_code}; see SONAR-SETUP.md')
        return result.json() if result.content else {}

    status = api('/api/system/status')
    if status.get('status') != 'UP':
        raise RuntimeError('SonarQube is not UP yet; finish starting it before initialization.')
    PRIVATE.mkdir(exist_ok=True)
    password_file = PRIVATE / 'sonar-admin-password.txt'
    token_file = PRIVATE / 'sonar-token.txt'
    if password_file.exists():
        client.auth = ('admin', password_file.read_text(encoding='utf-8').strip())
        if not api('/api/authentication/validate').get('valid'):
            raise RuntimeError('Stored local admin password is not valid. Use manual setup; no existing account was changed.')
    elif args.initialize_default_admin:
        client.auth = ('admin', 'admin')
        if not api('/api/authentication/validate').get('valid'):
            raise RuntimeError('Default credentials are unavailable. Existing installation requires manual setup.')
        password = secrets.token_urlsafe(32)
        # Persist first so a process interruption cannot lose a successfully changed password.
        private_write(password_file, password)
        api('/api/users/change_password', {'login': 'admin', 'previousPassword': 'admin', 'password': password})
        client.auth = ('admin', password)
    else:
        raise RuntimeError('First-time setup needs --initialize-default-admin or the manual steps in SONAR-SETUP.md.')

    projects = []
    for variant in ('vulnerable', 'fixed'):
        key = 'nexus-' + variant
        if not api('/api/projects/search?projects=' + key).get('components'):
            api('/api/projects/create', {'project': key, 'name': 'NEXUS - ' + variant.title(), 'visibility': 'private'})
        projects.append(key)
    expiry = (datetime.now(timezone.utc) + timedelta(days=7)).date().isoformat()
    if token_file.exists():
        previous_auth = client.auth
        client.auth = (token_file.read_text(encoding='utf-8').strip(), '')
        valid = api('/api/authentication/validate').get('valid')
        client.auth = previous_auth
    else:
        valid = False
    if not valid:
        generated = api('/api/user_tokens/generate', {'name': 'nexus-local-' + secrets.token_hex(6), 'expirationDate': expiry})
        private_write(token_file, generated['token'])
    analysis_files = [ROOT / 'reports/generated' / f'sonar-{variant}-{kind}.json'
                      for variant in ('vulnerable', 'fixed') for kind in ('issues', 'hotspots')]
    analysis_completed = all(path.exists() for path in analysis_files)
    report = {'utc': datetime.now(timezone.utc).isoformat(), 'server_status': status['status'],
              'projects': projects, 'token_file': '.runtime/sonar-token.txt',
              'admin_password_file': '.runtime/sonar-admin-password.txt',
              'analysis_completed': analysis_completed}
    (ROOT / 'reports/generated/sonar-setup.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PASS: local SonarQube initialized; two private projects and local token are ready.')
    print('Credentials are only in ignored .runtime files. Analysis completion is recorded in reports/generated/sonar-setup.json.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except requests.RequestException:
        print('FAIL: local SonarQube is unreachable; start it and follow reports/SONAR-SETUP.md.')
        sys.exit(1)
    except (RuntimeError, KeyError) as error:
        print(f'FAIL: {error}')
        sys.exit(1)
