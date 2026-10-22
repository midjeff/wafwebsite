"""Offline structure/security configuration checks, not a Docker runtime test."""
import ast
import json
from pathlib import Path
import sys
import yaml
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
errors = []


def check(condition, explanation):
    print(f"{'PASS' if condition else 'FAIL'} {explanation}")
    if not condition:
        errors.append(explanation)


for path in [*ROOT.glob('app/**/*.py'), *ROOT.glob('app-fixed/**/*.py'), *ROOT.glob('scripts/*.py'), *ROOT.glob('tests/*.py')]:
    try:
        ast.parse(path.read_text(encoding='utf-8'))
    except SyntaxError as error:
        errors.append(f'{path}: {error}')
check(not errors, 'Python source parses')
config = yaml.safe_load((ROOT / 'compose.yaml').read_text())
try:
    jsonschema.validate(config, json.loads((ROOT / 'tests/compose-spec.schema.json').read_text(encoding='utf-8')))
    check(True, 'Compose conforms to the official compose-spec JSON schema')
except jsonschema.ValidationError as error:
    check(False, f'Compose schema: {error.message}')
for name, service in config['services'].items():
    for port in service.get('ports', []):
        check(port.startswith('127.0.0.1:'), f'{name}: published port bound to loopback')
    for volume in service.get('volumes', []):
        check('docker.sock' not in volume, f'{name}: no Docker socket mount')
check(config['networks']['lab'].get('internal') is False, 'Application network explicitly permits external routing (internal: false)')
for name, port in [('vulnerable', '127.0.0.1:8080:5000'), ('waf', '127.0.0.1:8081:8080'), ('fixed', '127.0.0.1:8082:5000')]:
    service = config['services'][name]
    check(service.get('ports') == [port], f'{name}: exact loopback port mapping {port}')
    check(service.get('networks') == ['lab'] and 'network_mode' not in service, f'{name}: attached only to lab, no host network')
for name in ['vulnerable', 'fixed']:
    service = config['services'][name]
    check(service['read_only'] and service['cap_drop'] == ['ALL'], f'{name}: restricted container')
    check(not service.get('cap_add') and not service.get('privileged', False), f'{name}: no added capabilities or privileged mode')
    check(service.get('security_opt') == ['no-new-privileges:true'], f'{name}: no-new-privileges enforced')
    check(service.get('sysctls', {}).get('net.ipv4.ping_group_range') == '0 2147483647', f'{name}: unprivileged ICMP ping group range preserved')
    check('user' not in service or service['user'] == '10001:10001', f'{name}: image non-root user is not overridden')
    build = service.get('build', {})
    check(build.get('context') == '.' and build.get('dockerfile', 'Dockerfile') == 'Dockerfile'
          and build.get('args', {}).get('APP_DIR') == ('app' if name == 'vulnerable' else 'app-fixed'),
          f'{name}: shared Dockerfile builds the correct implementation')
    check(service['tmpfs'] == ['/tmp:size=16m,mode=1777'], f'{name}: tmpfs options are a single mount specification')
    check(service['volumes'] == [f'{name}_data:/data'], f'{name}: only dedicated database volume, no host directories')
env = dict(line.split('=', 1) for line in (ROOT / 'waf/waf.env').read_text().splitlines() if '=' in line)
check(env['BACKEND'] == 'http://vulnerable:5000', 'WAF uses same backend as port 8080')
check(env['MODSEC_RULE_ENGINE'] == 'On' and env['MODSEC_REQ_BODY_ACCESS'] == 'On', 'WAF blocking and request body inspection configured')
dockerfile = (ROOT / 'Dockerfile').read_text()
check('USER 10001:10001' in dockerfile, 'Application runs as non-root')
install = dockerfile.find('apt-get install -y --no-install-recommends iputils-ping')
remove_cap = dockerfile.find('RUN /usr/sbin/setcap -r /usr/bin/ping')
non_root = dockerfile.find('USER 10001:10001')
check(0 <= install < remove_cap < non_root, 'ping file capability removed after installation and before non-root USER')
check('|safe' not in ''.join(p.read_text(encoding='utf-8') for p in (ROOT / 'app-fixed/templates').glob('*.html')), 'Fixed templates do not bypass escaping')
for source in [ROOT / 'sast/lab-rules.yml', ROOT / 'sast/registry-python.yml']:
    rules = yaml.safe_load(source.read_text(encoding='utf-8'))
    check(bool(rules.get('rules')), f'{source.name}: nonempty rule configuration')
check('profiles' not in config['services']['waf'], 'Default compose starts the complete application stand')
rate_config = (ROOT / 'waf/login-rate.conf').read_text()
check('./waf/login-rate.conf:/etc/nginx/conf.d/login-rate.conf:ro' in config['services']['waf'].get('volumes', []),
      'WAF mounts the real nginx login rate configuration read-only')
check('"POST:/login" $realip_remote_addr;' in rate_config and 'limit_req_status 429;' in rate_config
      and 'limit_req_zone $login_rate_key' in rate_config,
      'nginx limits login POSTs by original peer and returns 429')
check('access_log /dev/stdout login_limits if=$log_login_attempt;' in rate_config
      and 'limit_req_log_level error;' in rate_config,
      'nginx writes rejected login requests to the captured container log')
check(all(int(config['services']['fixed'].get('environment', {}).get(key, 0)) > 0
          for key in ['LOGIN_MAX_FAILURES', 'LOGIN_WINDOW_SECONDS', 'LOGIN_BLOCK_SECONDS']),
      'Fixed login failure policy is explicitly configured with positive values')
check(all(not (ROOT / name / 'templates/lab.html').exists() for name in ['app', 'app-fixed']),
      'Attack instructions are absent from portal templates')
sys.exit(1 if errors else 0)
