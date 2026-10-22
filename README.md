# NEXUS — локальная лаборатория WAF и SAST

Корпоративный портал IT-поддержки на Flask / SQLite. Две самостоятельные реализации позволяют показать шесть сценариев атак, настоящий ModSecurity с OWASP CRS, статический анализ и исправления в коде. Все имена, письма, пароли и данные учебные.

**Фактическая проверка 22.10.2026:** Docker установлен; vulnerable, fixed и WAF запущены и healthy. После исправления ping полный `scripts/lab.ps1 test` завершился успешно: **54/54 HTTP-проверки и 5/5 проверок audit WAF**. Обычный ping отдельно прошёл в обоих контейнерах под UID 10001. Структурная проверка прошла. Ранее полученные 26 локальных тестов, 36 Windows HTTP-проверок и результаты Semgrep сохранены без повторного запуска. **SonarQube и выполнение JavaScript в браузере не проверены.** Полный протокол: [reports/VERIFICATION.md](reports/VERIFICATION.md).

## Быстрый запуск на Windows

Нужен Docker Desktop с **Linux containers** и Docker Compose v2. Python и Node.js для контейнерного запуска не нужны. Для основных сервисов разумно выделить Docker около 2 ГБ RAM; вместе с SonarQube — 6–8 ГБ. Первый запуск загружает образы и Python-пакеты из официальных реестров.

1. Установите/откройте Docker Desktop вручную: [официальная инструкция Windows](https://docs.docker.com/desktop/setup/install/windows-install/).
2. Дождитесь готовности Docker Engine. Если Docker Desktop просит включить WSL 2 или виртуализацию, выполните инструкции производителя самостоятельно. Проект не устанавливает WSL и не изменяет настройки Windows.
3. В PowerShell:

```powershell
cd C:\Users\Shwepes\wafwebsite
docker version
docker compose version
docker info --format '{{.OSType}}'
docker compose up --build --force-recreate -d --wait
docker compose ps
```

Значение OSType должно быть `linux`. Основная команда запускает только vulnerable, fixed и waf. В Compose предусмотрены healthchecks; дождитесь `healthy`. Удобный вариант с ожиданием готовности:

```powershell
.\scripts\lab.ps1 start
```

Если политика PowerShell запрещает запуск локального скрипта, можно вызвать его **на один процесс**, не меняя системную политику:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\lab.ps1 start
```

## Адреса и аккаунты

| Адрес | Назначение |
|---|---|
| http://localhost:8080 | Уязвимое приложение напрямую |
| http://localhost:8081 | Тот же backend и та же БД через настоящий WAF |
| http://localhost:8082 | Исправленное приложение без WAF, отдельная БД |
| http://localhost:9000 | SonarQube после запуска профиля analysis |
| `/lab` на любом приложении | Пояснения и учебные строки, без автоматического запуска атак |

| Пользователь | Логин | Пароль | Личная заявка |
|---|---|---|---|
| Алиса Морозова | `alice` | `Alice-Lab-2026!` | `1001` |
| Борис Волков | `bob` | `Bob-Lab-2026!` | `1002` |

Общая заявка `1003` доступна обоим пользователям. `1004` — решённая заявка Алисы. Дополнительные учебные сотрудники: `it / IT-Lab-2026!`, `elena / Elena-Lab-2026!`. Для IDOR и Stored XSS используйте обычное и приватное окно браузера: вкладки одного профиля разделяют cookies. Уязвимая и исправленная версии имеют разные имена session-cookie; 8080/8081 используют одну уязвимую сессию, поскольку порт не изолирует cookies.

## Команды управления

```powershell
.\scripts\lab.ps1 start          # сборка, запуск, ожидание healthy
.\scripts\lab.ps1 status         # состояние контейнеров
.\scripts\lab.ps1 test           # все три варианта + корреляция audit WAF
.\scripts\lab.ps1 logs           # сохранить logs/waf.log и показать конец
.\scripts\lab.ps1 clean-comments # восстановить комментарии общей заявки
.\scripts\lab.ps1 reset          # восстановить ОБЕ учебные БД
.\scripts\lab.ps1 stop           # остановить, сохранив данные
.\scripts\lab.ps1 sonar          # SonarQube + PostgreSQL, ждать готовности
.\scripts\lab.ps1 scan-semgrep   # 4 сканирования: 2 версии × 2 набора
.\scripts\lab.ps1 scan-sonar     # 2 проекта, затем экспорт результатов
.\scripts\lab.ps1 scan           # Semgrep, затем SonarQube
```

`start` и `test` пересоздают контейнеры стенда, сохраняя named volumes. Это также обновляет адрес backend в nginx после пересборки приложений: старый WAF может удерживать прежний IP. `reset` удаляет созданные в портале учебные заявки/комментарии и возвращает fixtures. SonarQube не затрагивается. `test` создаёт учебные заявки и очищает комментарии #1003 перед каждым вариантом и после проверки. Старые данные SonarQube сохраняются в named volumes; не используйте `docker compose down -v`, если хотите их сохранить.

Первичная настройка SonarQube и ввод токена только в память текущего процесса: [reports/SONAR-SETUP.md](reports/SONAR-SETUP.md). В репозитории нет настоящих токенов. Пароль `sonar-lab-only` относится только к внутренней учебной БД PostgreSQL, порт БД не публикуется.

## Что реализовано

- Русскоязычный адаптивный интерфейс: боковое меню, обзор, таблица заявок, карточки сотрудников, комментарии, документы, диагностика, лабораторная страница. Локальные CSS, без CDN и сторонних шрифтов.
- Настоящие подписанные сессии, хеши паролей, CSRF-токены форм, SQLite с сохранением данных. Это не выбор пользователя через `user_id` в URL.
- SQLi в поиске, reflected XSS в приветствии, stored XSS в комментариях, shell injection в ping, path traversal при чтении документов, IDOR в доступе к заявке.
- В `app-fixed/`: SQL-параметры, автоматическое экранирование Jinja, ping без shell и с проверкой loopback IP, канонический путь с проверкой каталога, проверка автора/участника на GET и POST. CSP — дополнительная защита; XSS устранён самим экранированием.
- WAF работает отдельным reverse proxy; фильтрация в Flask не имитируется. Стандартный CRS PL1, режим On, проверка query и POST. Исходящие тела отключены намеренно для чистоты Stored XSS-эксперимента.

## Структура

```text
app/                  уязвимые маршруты, SQLite, шаблоны, локальные стили
app-fixed/            отдельная исправленная реализация с тем же интерфейсом
  main.py             маршруты и проверки
  db.py               схема и искусственные fixtures
  process.py          ограничения времени и объёма вывода процесса
  documents/          разрешённые инструкции
  lab-only.txt        учебный маркер вне documents/ для traversal
Dockerfile            non-root Python/Waitress, ping, healthcheck
compose.yaml          три точки входа, профили checks / analysis / tools
waf/                  настройки и пояснения реального ModSecurity
sast/                 SonarScanner, готовый snapshot и собственные правила
scripts/              PowerShell-команды, SAST, экспорт, developer preview
tests/                Flask-тесты, HTTP-сценарии, корреляция audit
logs/                 место для реальных журналов WAF
reports/              отчёты, сценарий защиты, шпаргалка, статус проверки
reports/generated/    реальные JSON/SARIF/логи инструментов
.runtime/             игнорируемые данные только локального developer preview
```

Контейнер приложения не получает исходники через bind mount: код копируется в образ. Единственный том — собственная БД `/data`. Нет Docker socket, пользовательских каталогов или настоящих секретов. Приложения работают как UID/GID 10001 с read-only корнем, `cap_drop: ALL`, `no-new-privileges` и лимитами памяти/процессов. Сеть `lab` — обычная bridge-сеть с `internal: false`: внешняя маршрутизация разрешена. Порты опубликованы только на `127.0.0.1`: 8080 → vulnerable:5000, 8081 → waf:8080, 8082 → fixed:5000. Эти параметры проверены и в конфигурации, и в работающих контейнерах; это не полная проверка всех границ контейнерной изоляции.

У установленного `/usr/bin/ping` была файловая capability `cap_net_raw=ep`. При пустом capability bounding set запуск файла завершался `operation not permitted` ещё до отправки пакета. Общий Dockerfile теперь выполняет `RUN /usr/sbin/setcap -r /usr/bin/ping` после установки пакета и до `USER 10001:10001`. Обычный ping работает через непривилегированные ICMP-сокеты благодаря сохранённому `net.ipv4.ping_group_range: "0 2147483647"`. NET_RAW, privileged, root и запуск через системный загрузчик не используются. Проверка: [generated/ping-runtime.json](reports/generated/ping-runtime.json).

## Материалы для сдачи

- [Сценарий на 7–10 минут](reports/DEMO-RU.md).
- [Задание 1: WAF, английский отчёт](reports/TASK-1-WAF.md).
- [Задание 2: SAST, английский отчёт](reports/TASK-2-SAST.md).
- [Таблица шести сценариев](reports/RESULTS.md).
- [Шпаргалка для защиты](reports/CHEATSHEET-RU.md).
- [Какие скриншоты сделать](reports/SCREENSHOTS.md).
- [Версии и официальные источники](reports/VERSIONS.md).
- [Проверено / не проверено](reports/VERIFICATION.md).

## Если что-то не запускается

| Симптом | Действие |
|---|---|
| `docker` не найден | Установить/открыть Docker Desktop, затем новое окно PowerShell. Проверить `docker version`. |
| Engine недоступен | Дождаться запуска Desktop; проверить Linux containers. |
| Порт занят | `Get-NetTCPConnection -LocalPort 8080,8081,8082,9000 -ErrorAction SilentlyContinue`. Остановить только свой конфликтующий процесс. |
| WAF 502 / unhealthy | `docker compose logs vulnerable waf`; дождаться backend healthy, проверить `BACKEND` в `waf/waf.env`. |
| После пересборки через WAF открывается исправленная версия или появляется неожиданный 403 IDOR | Выполнить `scripts/lab.ps1 start`: он пересоздаёт WAF вместе с приложениями и обновляет разрешение имени backend. Проверить cookie `nexus_vulnerable` на 8081. |
| `exec /usr/bin/ping: operation not permitted` | Пересобрать через `scripts/lab.ps1 start`; проверить отсутствие файловой capability (`getcap /usr/bin/ping`), UID 10001 и `ping_group_range`. Не добавлять NET_RAW. |
| Обычная форма получает 403 за WAF | Сохранить audit, найти реальный rule ID и matched variable. Не отключать весь маршрут и не подменять результат теста. |
| XSS появляется после включения WAF | Очистить ранее сохранённые комментарии: WAF не удаляет данные. |
| CSRF / форма устарела | Обновить страницу после входа/выхода/сброса. Не переносить CSRF между сессиями. |
| SonarQube падает с `vm.max_map_count` | См. отдельную ручную инструкцию в `reports/SONAR-SETUP.md`; системные настройки автоматически не меняются. |
| SonarScanner 401/403 | Проверить срок токена и права Execute Analysis/Browse для обоих проектов. Не вставлять токен в командную строку или properties. |
| Ненулевой код Semgrep | Открыть `semgrep-*.log` и errors в JSON. Находки сами по себе не дают ненулевой код; технические ошибки дают FAIL. |
| WAF audit test FAIL при 403 | Проверить Native/Serial, stdout, части ABFHZ и свежесть логов. Сам по себе HTTP 403 не является доказательством WAF. |

В PowerShell используйте `curl.exe`, а не алиас `curl`. Пример traversal после входа через портал: `http://localhost:8080/download?file=..%2Flab-only.txt`. Значение передаётся в query, поэтому браузер не удалит `../` нормализацией URL-пути.

## Дополнительный запуск разработчика без Docker

Этот путь использовался только для доступных проверок. Он требует Python и **не предоставляет WAF**:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tests\requirements-local.txt
.\.venv\Scripts\python.exe -X utf8 tests\unit_checks.py
.\.venv\Scripts\python.exe -X utf8 scripts\verify-project.py
.\.venv\Scripts\python.exe -X utf8 scripts\serve.py app --port 8080
# В другом окне:
.\.venv\Scripts\python.exe -X utf8 scripts\serve.py app-fixed --port 8082
```

Windows shell использует `127.0.0.1 & echo LAB_TEST`; основная Linux-контейнерная демонстрация использует `127.0.0.1; echo LAB_TEST`. Не смешивайте результаты этих двух сред. Локальный preview слушает только 127.0.0.1, но не имеет контейнерной изоляции; для демонстрации преподавателю используйте Docker.
