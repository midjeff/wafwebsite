# Зафиксированные версии и официальные источники

Проверено 21.10.2026. Docker Hub API подтвердил существование **каждого** выбранного тега и вернул digest. Машиночитаемые ответы (выбранные поля, архитектуры, дата обновления, ссылки) находятся в `generated/versions.json`. Это исторический снимок Registry от 21.10.2026. На 22.10.2026 образы приложений и checks собраны, приложения и WAF реально запущены; см. VERIFICATION.md и generated/ping-runtime.json. SonarQube, PostgreSQL и Scanner в этой проверке не запускались; прежний Semgrep запускался локально, не в Docker. Метаданные versions.json не переписаны как runtime-доказательство.

| Компонент | Зафиксированный выбор |
|---|---|
| Python / приложение и HTTP checks | `python:3.12.15-slim-bookworm` + digest в Dockerfile |
| Flask | `3.1.3` |
| Werkzeug / Jinja2 / MarkupSafe | `3.1.9` / `3.1.6` / `3.0.4` |
| itsdangerous / click / blinker | `2.2.0` / `8.4.2` / `1.9.0` |
| Waitress | `3.0.2` |
| SQLite | Модуль Python stdlib; точная SQLite runtime version определяется образом Python |
| OWASP CRS / nginx image | `owasp/modsecurity-crs:4.30.0-nginx-202610180210` + digest |
| ModSecurity / nginx | В официальном README выбранного поколения: `3.0.17` / `1.30.6`; фактический runtime ещё проверить |
| SonarQube Community Build | `sonarqube:26.10.0.133078-community` + digest |
| SonarScanner CLI Docker / CLI | `12.2.0.4256_8.1.0` / `8.1.0`, digest закреплён |
| PostgreSQL | `postgres:17.9-bookworm` + digest |
| Semgrep CE | `semgrep/semgrep:1.181.0` + digest; локальный реальный запуск той же версии |
| Готовые правила Semgrep | Snapshot `p/python`, 151 правило; SHA-256 в versions.json и semgrep-summary.json |
| Requests для HTTP tests | `2.32.5` |
| Локальная структурная проверка | PyYAML `6.0.3`, jsonschema `4.25.1` |

Выбирались доступные стабильные теги, без `latest`/canary. Например, Registry показывал Semgrep 1.182.0 как canary-сборку и stable latest 1.181.0; закреплена последняя. PostgreSQL 17 выбран как поддерживаемая стабильная ветка для лаборатории, а не как обещание самого нового major. Digest фиксирует образ, даже если тег обновится. Пакеты ОС внутри собственного app-image устанавливаются при сборке из Debian repository и не снапшотированы; строгая побитовая воспроизводимость потребует сохранённого digest уже собранного app-image. Python-зависимости приложения закреплены полностью в requirements.txt.

## Первичные источники, использованные при настройке

1. [Flask changelog](https://flask.palletsprojects.com/en/stable/changes/): релиз 3.1.3 и исправление обработки session access.
2. [OWASP CRS Docker README](https://github.com/coreruleset/modsecurity-crs-docker): формат датированных тегов, BACKEND, PORT, MODSEC_*, paranoia, anomaly thresholds, audit и healthchecks.
3. [Docker Hub: OWASP CRS](https://hub.docker.com/r/owasp/modsecurity-crs/tags): выбранный тег подтверждён API.
4. [SonarQube Docker deployment](https://www.sonarsource.com/products/sonarqube/deployment/docker/): официальный Community Build image.
5. [Официальный Dockerfile Community Build](https://github.com/SonarSource/docker-sonarqube/blob/master/community-build/Dockerfile): пользователь sonarqube, каталоги данных и доступность curl для healthcheck.
6. [SonarScanner CLI](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner): Docker invocation, SONAR_HOST_URL/SONAR_TOKEN, права mounted directories и cache.
7. [SonarQube feature comparison](https://docs.sonarsource.com/sonarqube-community-build/feature-comparison-table): ограничение анализа веток в Community Build.
8. [SonarQube source repository](https://github.com/SonarSource/sonarqube): отличие бесплатной сборки от коммерческих advanced security capabilities.
9. [SonarQube Linux prerequisites](https://docs.sonarsource.com/sonarqube-community-build/server-installation/pre-installation/linux): требования Elasticsearch к Linux host/VM.
10. [SonarQube Web API](https://docs.sonarsource.com/sonarqube-community-build/extension-guide/web-api): получение данных; точные endpoints доступны также в `/web_api` работающего сервера.
11. [Semgrep Community Edition](https://semgrep.dev/products/community-edition/): локальный свободный движок, Docker и форматы результатов.
12. [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference): `scan`, JSON/SARIF, exit codes, metrics и OSS mode.
13. [Снимок готовых правил p/python](https://semgrep.dev/c/p/python): ответ сохранён в `sast/registry-python.yml`.
14. [Docker Desktop Windows](https://docs.docker.com/desktop/setup/install/windows-install/): ручная подготовка окружения.
15. [Официальная JSON Schema Compose](https://github.com/compose-spec/compose-spec/blob/main/schema/compose-spec.json): сохранена в `tests/compose-spec.schema.json`, успешно применена к compose.yaml. Источник схемы — Compose Specification, не собственная имитация Compose CLI.

После запуска можно зафиксировать runtime версии дополнительными командами:

```powershell
docker compose exec -T vulnerable python -c "import sys, sqlite3; print(sys.version); print(sqlite3.sqlite_version)"
docker compose exec -T waf nginx -V
docker compose --profile tools run --rm --no-deps --entrypoint semgrep semgrep --version
docker compose --profile tools run --rm --no-deps scanner --version
curl.exe http://localhost:9000/api/server/version
```

Не заменяйте реальные версии в отчёте предполагаемыми по названию образа.
