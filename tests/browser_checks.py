"""Real browser execution on the three fixed localhost endpoints; isolated users."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BASES = {'vulnerable': 'http://localhost:8080', 'waf': 'http://localhost:8081', 'fixed': 'http://localhost:8082'}


def clean():
    for service in ('vulnerable', 'fixed'):
        subprocess.run(['docker', 'compose', 'exec', '-T', service, 'flask', '--app', 'portal.main:create_app', 'clean-comments'],
                       cwd=ROOT, check=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--channel', choices=['chromium', 'chrome', 'msedge'], default='chromium')
    args = parser.parse_args()
    output = ROOT / 'reports/generated'
    screenshots = ROOT / 'reports/screenshots'
    screenshots.mkdir(exist_ok=True)
    results = []

    def record(name, passed, **evidence):
        results.append({'name': name, 'passed': bool(passed), **evidence})
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, **({'channel': args.channel} if args.channel != 'chromium' else {}))
            version = browser.version
            for mode, base in BASES.items():
                clean()
                contexts, pages, dialogs = [], [], [[], []]
                for index, (username, password) in enumerate([('alice', 'Alice-Lab-2026!'), ('bob', 'Bob-Lab-2026!')]):
                    context = browser.new_context(viewport={'width': 1280, 'height': 900})
                    page = context.new_page()
                    def handle_dialog(dialog, index=index):
                        dialogs[index].append(dialog.message)
                        dialog.accept()
                    page.on('dialog', handle_dialog)
                    page.goto(base + '/login')
                    page.get_by_label('Логин', exact=True).fill(username)
                    page.get_by_label('Пароль', exact=True).fill(password)
                    page.get_by_role('button', name='Войти в портал').click()
                    page.wait_for_url(base + '/')
                    identity = context.request.get(base + '/api/me').json()
                    record(f'{mode}: separate session {username}', identity['username'] == username)
                    contexts.append(context)
                    pages.append(page)
                pages[0].screenshot(path=str(screenshots / f'{mode}-dashboard.png'), full_page=True)
                record(f'{mode}: normal UI', 'лаборатор' not in pages[0].locator('body').inner_text().lower())

                for payload, marker in [('<script>alert("BROWSER_REFLECTED")</script>', 'BROWSER_REFLECTED'),
                                        ('<svg onload=alert("BROWSER_SVG")>', 'BROWSER_SVG')]:
                    dialogs[0].clear()
                    response = pages[0].goto(base + '/greeting?' + urlencode({'name': payload}))
                    pages[0].wait_for_timeout(350)
                    if mode == 'vulnerable':
                        passed = response.status == 200 and marker in dialogs[0]
                    elif mode == 'fixed':
                        passed = response.status == 200 and not dialogs[0] and payload in pages[0].locator('body').inner_text()
                    else:
                        passed = response.status == 403 and not dialogs[0]
                    record(f'{mode}: {marker}', passed, status=response.status, dialogs=list(dialogs[0]))

                for payload, marker in [('<script>alert("BROWSER_STORED")</script>', 'BROWSER_STORED'),
                                        ('<img src=x onerror=alert("BROWSER_IMAGE")>', 'BROWSER_IMAGE')]:
                    clean()
                    pages[0].goto(base + '/tickets/1003')
                    pages[0].get_by_label('Ваш комментарий').fill(payload)
                    with pages[0].expect_response(lambda r: r.request.method == 'POST' and '/tickets/1003' in r.url) as sent:
                        pages[0].get_by_role('button', name='Отправить комментарий').click()
                    dialogs[1].clear()
                    pages[1].goto(base + '/tickets/1003')
                    pages[1].wait_for_timeout(350)
                    body = pages[1].locator('body').inner_text()
                    if mode == 'vulnerable':
                        passed = sent.value.status == 302 and marker in dialogs[1]
                    elif mode == 'fixed':
                        passed = sent.value.status == 302 and not dialogs[1] and payload in body
                    else:
                        passed = sent.value.status == 403 and not dialogs[1] and marker not in body
                    record(f'{mode}: Bob executes {marker}', passed, post_status=sent.value.status, dialogs=list(dialogs[1]))
                    pages[1].screenshot(path=str(screenshots / f'{mode}-{marker.lower()}.png'), full_page=True)
                # Same backend/data: payload inserted directly is still served through WAF.
                if mode == 'waf':
                    clean()
                    pages[0].goto(BASES['vulnerable'] + '/tickets/1003')
                    pages[0].get_by_label('Ваш комментарий').fill('<script>alert("EXISTING_STORED")</script>')
                    pages[0].get_by_role('button', name='Отправить комментарий').click()
                    pages[0].wait_for_load_state()
                    dialogs[1].clear()
                    pages[1].goto(base + '/tickets/1003')
                    pages[1].wait_for_timeout(350)
                    record('WAF serves existing Stored XSS from direct backend', 'EXISTING_STORED' in dialogs[1], dialogs=list(dialogs[1]))
                clean()
                pages[0].goto(base + '/')
                pages[0].set_viewport_size({'width': 390, 'height': 844})
                pages[0].screenshot(path=str(screenshots / f'{mode}-mobile.png'), full_page=True)
                record(f'{mode}: mobile has no horizontal overflow', pages[0].evaluate('document.documentElement.scrollWidth <= window.innerWidth'))
                for context in contexts:
                    context.close()
            browser.close()
    except Exception as error:
        version = locals().get('version', None)
        record('technical_error', False, error=f'{type(error).__name__}: {error}')
    finally:
        clean()
    report = {'utc': datetime.now(timezone.utc).isoformat(), 'browser': args.channel, 'version': version,
              'headless': True, 'results': results, 'passed': bool(results) and all(r['passed'] for r in results)}
    (output / 'browser-checks.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
