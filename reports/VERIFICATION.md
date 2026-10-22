# Фактически выполненные проверки

Обновлено 22.10.2026, Asia/Qyzylorda (UTC+5). Docker Desktop установлен; vulnerable, fixed и waf запущены и healthy. SonarQube/PostgreSQL запущены через Compose; API вернул `UP`; два проекта отсканированы, JSON-результаты сохранены.

| Проверка | Результат | Доказательства / границы |
|---|---|---|
| Пересборка vulnerable и fixed | **PASS** | Общий Dockerfile; снятие capability выполнено для обоих образов |
| Обычный ping 127.0.0.1 | **2/2 PASS** | `generated/ping-runtime.json`: штатный UID/GID 10001, exit 0, 1 received, 0% packet loss |
| Docker HTTP: vulnerable | **24/24 PASS** | `generated/http-vulnerable.json`, Linux |
| Docker HTTP: WAF | **24/24 PASS** | `generated/http-waf.json`, Linux |
| Docker HTTP: fixed | **24/24 PASS** | `generated/http-fixed.json`, Linux |
| Полный `scripts/lab.ps1 test` | **PASS, exit 0** | 72/72 HTTP-проверки; все три сценария brute force также прошли |
| Корреляция audit ModSecurity/CRS | **10/10 PASS** | `generated/waf-evidence.json`, `logs/waf.log`; пять базовых и пять альтернативных блокировок подтверждены по CRS audit |
| Ограничение перебора через nginx | **6/6 журналируемых 429** | `generated/nginx-login-evidence.json`, `logs/login-rate.log`; это `limit_req`, не ModSecurity/CRS |
| Flask/SQLite/process проверки | **34/34 PASS** | `generated/local-checks.json`; Windows |
| Лимитер fixed и параллельные процессы | **9/9 PASS** | `generated/login-limit-checks.json`; четыре процесса и 12 одновременных запросов на бюджет |
| Исполнение XSS и адаптивность в браузере | **25/25 PASS** | `generated/browser-checks.json`, `reports/screenshots/`; headless Chrome 155.0.8059.85, Alice/Bob в отдельных контекстах |
| Структура / Python syntax / Compose Schema | **61/61 PASS, exit 0** | `scripts/verify-project.py`, вывод `generated/structure-check.txt` |
| Синтаксис изменённого PowerShell-скрипта | **PASS** | PowerShell Parser: 0 ошибок в `scripts/lab.ps1` |
| Runtime-порты, сеть, ограничения приложений | **PASS** | `generated/ping-runtime.json`; Docker inspect и /proc, не только YAML |
| Страница входа с хоста на 8080/8081/8082 | **3/3 PASS** | HTTP 200; cookie vulnerable на 8080/8081, fixed на 8082; без запуска браузера |
| Ранее: Flask/SQLite/процессы, Windows | **26/26 PASS**, исторический результат | `generated/local-checks.json`, в этом сеансе не перезапускались |
| Ранее: HTTP Windows preview | **36/36 PASS**, исторический результат | `generated/local-http/`, по 18 на две версии; не смешивать с 54 контейнерными |
| Semgrep CE 1.181.0 | **8 успешных запусков: 4 до и 4 после изменений** | Registry 0/0, custom 5/1 в каждом прогоне; новые before/after JSON/SARIF/log отдельно, исходный `semgrep-summary.json` сохранён без изменения |
| SonarQube / SonarScanner | **2/2 анализа и экспорт PASS** | Vulnerable: 3 Issues, 0 Hotspots; fixed: 1 Issue, 0 Hotspots; оба quality gate `OK`. JSON: `generated/sonar-*.json` |

## Причина и исправление ping

До исправления `/usr/bin/ping` имел файловую capability `cap_net_raw=ep`, а capability bounding set процесса был пустым из-за `cap_drop: ALL`. Попытка исполнения такого файла завершалась EPERM (`operation not permitted`) ещё до работы ping. Это не потеря ICMP-пакета и не следствие `lab.internal`.

В общий Dockerfile после установки пакета и до `USER 10001:10001` добавлено:

```dockerfile
RUN /usr/sbin/setcap -r /usr/bin/ping
```

После пересборки в обоих контейнерах `getcap /usr/bin/ping` пуст, атрибут `security.capability` отсутствует. UID/GID — 10001, CapInh/CapPrm/CapEff/CapBnd/CapAmb равны нулю, NoNewPrivs=1, Seccomp=2. Сохранены read-only rootfs, `cap_drop: ALL`, `no-new-privileges:true`, отсутствие cap_add и privileged. Значение `net.ipv4.ping_group_range` — `0 2147483647`, `icmp_echo_ignore_all` — 0. Рабочий ping использует непривилегированные ICMP-сокеты. Root, NET_RAW и запуск через системный загрузчик не понадобились.

Проверены обычные команды без `-u` и обходных способов запуска:

```powershell
docker compose exec -T vulnerable ping -c 1 -W 2 127.0.0.1
docker compose exec -T fixed ping -c 1 -W 2 127.0.0.1
```

Сеть `nexus-security-lab_lab` имеет Driver=bridge, Internal=false. Публикации: только `127.0.0.1:8080:5000`, `127.0.0.1:8081:8080`, `127.0.0.1:8082:5000`. Внешняя маршрутизация сети разрешена. Это проверено через Docker inspect; полной проверки всех границ контейнерной изоляции не проводилось.

## Промежуточный FAIL и устранение причины

Первый прогон после исправления ping дал **53/54 HTTP и 5/5 audit**: ping уже прошёл, но IDOR через WAF неожиданно вернул 403. Этот результат сохранён в `generated/ping-fix-first-run/`, включая исходный журнал; он не подменён успешным.

В его журнале запросы через WAF использовали cookie `nexus_fixed`, а ответ на `/tickets/1002` содержал CSP исправленного приложения и 403 без сообщения блокировки CRS. Это подтверждает обращение WAF к fixed вместо vulnerable. Конфигурация nginx содержит буквальный `proxy_pass http://vulnerable:5000`; старый процесс nginx удерживал адрес, разрешённый до пересоздания приложений. Наличие `resolver` само по себе не делает такой буквальный proxy_pass динамическим.

В `scripts/lab.ps1` команды start/test теперь выполняют `compose up --build --force-recreate`: весь стенд пересоздаётся с сохранением томов, WAF стартует после healthy vulnerable и заново определяет адрес. Правила WAF, код приложений и ожидания тестов не менялись. После этого полный прогон дал **54/54 + 5/5**, IDOR через WAF — 200, fixed — 403. Дополнительный запрос с хоста подтвердил cookie `nexus_vulnerable` на 8081. Во время диагностики Docker Engine также временно остановился; Docker Desktop был запущен снова.

## Подтверждённые правила WAF

| Сценарий | Детектирующие правила | Итог |
|---|---|---|
| SQLi | 942100 — libinjection SQLi | 403, score 5 |
| Reflected XSS | 941100, 941110, 941160, 941390 — libinjection, script tag, HTML injection, JavaScript method | 403, score 20 |
| Stored XSS | 941100, 941110, 941160, 941390 | POST 403, score 20; payload не сохранён |
| Command Injection | 932235 — Unix command injection | 403, score 5 |
| Path Traversal | 930110 — traversal pattern | 403, score 5 |

Во всех пяти транзакциях также присутствует 949110 — превышение порога inbound anomaly score. Это правило принимает решение по сумме; самостоятельным доказательством распознавания класса атаки его не считали. Полные сообщения и уникальные case_id находятся в `generated/waf-evidence.json`. IDOR через WAF остался доступен: WAF не проверяет владельца заявки.

## Границы проверки и оставшиеся шаги

В каждом режиме 18 HTTP-проверок: два входа, четыре обычные страницы, поиск/скачивание/создание заявки/комментарий/ping, чистое состояние перед Stored XSS и шесть демонстраций. Linux Command Injection подтверждён реальным `LAB_TEST` от shell с разделителем `;`. XSS проверен по raw/escaped HTML и сохранению между отдельными сессиями. Браузерные alert и отсутствие исполнения в fixed этим не доказаны. Пять audit-проверок идут отдельно от 54 HTTP-проверок.

Для завершения сдачи: подготовить демонстрацию по `DEMO-RU.md`, просмотреть сохранённые скриншоты по `SCREENSHOTS.md` и в SonarQube вручную рассмотреть открытые S4502 предупреждения CSRF. Сервер, два анализа, экспорты и оба quality gate уже проверены. Успех выбранных тестов не доказывает блокировку всех вариантов атак.

## CSRF review (2026-10-22)

Direct fixed-app CSRF verification passed **17/17** without sending requests through WAF. Missing, invalid, and cross-session tokens were rejected (HTTP 400) for all five mutating routes; valid same-session tokens were accepted for login and ticket creation. Evidence: `generated/csrf-checks.json`; run `.venv\Scripts\python.exe tests\csrf_checks.py` from the repository root.

`python:S4502` was reported at `app/main.py:29` (`nexus-vulnerable`) and `app-fixed/main.py:30` (`nexus-fixed`). The global checks at `app/main.py:45-51` and `app-fixed/main.py:50-58` protect every POST before route dispatch. No CSRF defect was reproduced. SonarQube comments now contain the evidence and code references; the status is `FALSE_POSITIVE` in both projects. The Sonar issue exports were refreshed. This supersedes the earlier note above that requested review of open S4502 findings.
Additional reruns for the S4502 review: the established Flask/SQLite/process suite passed **34/34** for both vulnerable and fixed code, and the project structure/configuration verifier passed **61/61**. Neither run changes or reclassifies the preserved Semgrep before/after results.