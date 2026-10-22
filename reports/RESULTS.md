# Фактические результаты

Обновлено 22.10.2026. Полный `scripts/lab.ps1 test`: **72/72 HTTP проверки**, **10/10 подтверждённых CRS audit блокировок** и **3/3 brute-force сценария**. По 24 HTTP сценария прошли на vulnerable, WAF и fixed.

| Сценарий | 8080 напрямую | 8081 через WAF | 8082 fixed |
|---|---|---|---|
| SQL Injection | Инъекция меняет результат SQLite вплоть до UNION | 403, подтверждено audit CRS | Параметризованный SQL, строка инъекции не расширяет результат |
| Reflected XSS | Chrome исполнил script и SVG event handler | 403, диалогов нет | Вывод экранирован, диалогов нет |
| Stored XSS | Alice сохранила два варианта; Bob их исполнил в отдельной сессии | POST 403, не сохранены | Jinja экранирует; Chrome не вызвал диалог |
| Command Injection | Linux shell выполнил команду после `;` | 403, CRS 932235 | Вход проходит allowlist адреса; shell не запускается |
| Path Traversal | Путь выше documents прочитан | 403, CRS 930110 | Путь отклонён, файлы из каталога документов доступны |
| IDOR | Alice читает/изменяет чужую заявку | 200: WAF не знает владельца | Серверная проверка владельца отклоняет чужой доступ |

## Перебор паролей

| Вариант | Результат |
|---|---|
| 8080 vulnerable | 9 отказов, 10-й верный пароль выдал аутентификацию |
| 8081 WAF | 429 от nginx `limit_req`; новая cookie-сессия и поддельные forwarding-заголовки лимит не обходят |
| 8082 fixed | 429 по SQLite-счётчикам аккаунта и источника; после окна блокировки вход восстановился |

Дополнительно: **34/34** Flask/SQLite/process теста, **9/9** проверок fixed-лимитера (включая 4 процесса), **25/25** Chrome/UI проверок. WAF-перебор — nginx `limit_req`, а не CRS. Semgrep до/после: два успешных полных прогона (Registry 0/0, custom 5/1 в каждом); отчёты с хешами исходников сохранены отдельно. SonarQube: vulnerable 3 Issues/0 Hotspots, fixed 1 Issue/0 Hotspots; quality gate `OK` обоих; сервер `UP`.

Машинные отчёты: `generated/http-*.json`, `generated/waf-evidence.json`, `generated/bruteforce-*.json`, `generated/nginx-login-evidence.json`, `generated/browser-checks.json`.

## CSRF / SonarQube `python:S4502`

SonarQube reports the rule at `app/main.py:29` in `nexus-vulnerable` and `app-fixed/main.py:30` in `nexus-fixed`. The finding is on Flask app construction; both code trees have a global POST check before route execution (`app/main.py:45-51`, `app-fixed/main.py:50-58`). It creates a random token in the signed session, compares with `secrets.compare_digest`, and rejects missing or non-matching values. All five state-changing POST routes are covered: login, logout, new ticket, ticket comment, and diagnostics. The corresponding forms carry the token.

Direct tests against fixed Flask (without WAF), using an isolated temporary SQLite database, passed **17/17**. On each POST route, missing, invalid, and another session's token returned HTTP 400. A valid token from its own session was accepted for login and ticket creation. Evidence: `generated/csrf-checks.json`; reproducible with `.venv\Scripts\python.exe tests\csrf_checks.py`. No CSRF defect was reproduced. The findings were documented in SonarQube and set to `FALSE_POSITIVE` in both projects. No intentional vulnerable demonstration was changed.