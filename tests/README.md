# Проверки

`unit_checks.py` — стандартный unittest, реальные временные SQLite-БД и subprocess. Проверяет шесть сценариев, нормальную работу, сохранение при новом экземпляре приложения, две сессии, CSRF, альтернативные вводы, очистку комментариев и ограничения процесса. Все 26 тестов фактически прошли на Windows.

`http_checks.py` — реальные HTTP-запросы к Waitress или контейнерам. По 18 проверок на режим, отдельные cookie jars Алисы/Бориса, проверка содержимого и сохранения. Режим `waf` не эмулирует прокси. Linux — по умолчанию; `--platform windows` нужен только для локального developer preview. Для повторного запуска сначала очищайте shared comments; контейнерный PowerShell wrapper делает это сам.

`check_waf_logs.py` — проверяет настоящие Native audit transactions. Сопоставляет пять attack case IDs из HTTP-отчёта, статус 403 и сообщения с rule IDs; IDOR намеренно не ожидается среди блокировок. Без реального audit тест не считается пройденным.

`compose-spec.schema.json` — неизменённая схема из [официального Compose Specification](https://raw.githubusercontent.com/compose-spec/compose-spec/main/schema/compose-spec.json), загружена 21.10.2026. Применяется `scripts/verify-project.py` через jsonschema. Структурная валидация не запускает сервисы и не подтверждает доступность Docker Engine.

Контейнерные тесты требуют только Docker: `scripts/lab.ps1 test`. Для необязательных локальных тестов: `pip install -r tests/requirements-local.txt`. Для локального Semgrep: `pip install semgrep==1.181.0`, затем `python scripts/run_semgrep.py`. В обычном Windows-запуске все эти зависимости находятся в контейнерах, Python на хосте не нужен.

Проверки XSS здесь исследуют HTML. Исполнение JavaScript и визуальная корректность требуют браузера и действий из `reports/DEMO-RU.md`. Не отмечайте эти шаги как выполненные только на основании HTTP.
