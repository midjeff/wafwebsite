# Фактически выполненные проверки

Обновлено 22.10.2026, Asia/Qyzylorda (UTC+5). В машинных журналах время UTC, поэтому дата поздних проверок там ещё 21.10.2026. Docker Desktop установлен; vulnerable, fixed и waf запущены и healthy. SonarQube в этом сеансе не запускался.

| Проверка | Результат | Доказательства / границы |
|---|---|---|
| Пересборка vulnerable и fixed | **PASS** | Общий Dockerfile; снятие capability выполнено для обоих образов |
| Обычный ping 127.0.0.1 | **2/2 PASS** | `generated/ping-runtime.json`: штатный UID/GID 10001, exit 0, 1 received, 0% packet loss |
| Docker HTTP: vulnerable | **18/18 PASS** | `generated/http-vulnerable.json`, Linux |
| Docker HTTP: WAF | **18/18 PASS** | `generated/http-waf.json`, Linux |
| Docker HTTP: fixed | **18/18 PASS** | `generated/http-fixed.json`, Linux |
| Полный `scripts/lab.ps1 test` | **PASS, exit 0** | 54/54 HTTP-проверки, включая normal_ping во всех трёх вариантах |
| Корреляция audit ModSecurity/CRS | **5/5 PASS** | `generated/waf-evidence.json`, `logs/waf.log`; case_id + 403 + сообщение детектирующего правила |
| Структура / Python syntax / Compose Schema | **55/55 PASS, exit 0** | `scripts/verify-project.py`, вывод `generated/structure-check.txt` |
| Синтаксис изменённого PowerShell-скрипта | **PASS** | PowerShell Parser: 0 ошибок в `scripts/lab.ps1` |
| Runtime-порты, сеть, ограничения приложений | **PASS** | `generated/ping-runtime.json`; Docker inspect и /proc, не только YAML |
| Страница входа с хоста на 8080/8081/8082 | **3/3 PASS** | HTTP 200; cookie vulnerable на 8080/8081, fixed на 8082; без запуска браузера |
| Ранее: Flask/SQLite/процессы, Windows | **26/26 PASS**, исторический результат | `generated/local-checks.json`, в этом сеансе не перезапускались |
| Ранее: HTTP Windows preview | **36/36 PASS**, исторический результат | `generated/local-http/`, по 18 на две версии; не смешивать с 54 контейнерными |
| Ранее: Semgrep CE 1.181.0 | **4 успешных запуска**, без изменений | Registry 0/0, custom 5/1; JSON/SARIF/log и `semgrep-summary.json` сохранены, нового сканирования не было |
| SonarQube / SonarScanner | **НЕ ВЫПОЛНЕНО** | Нужны запуск, первоначальная настройка, сканирование и экспорт |
| Исполнение XSS в браузере | **НЕ ПРОВЕРЕНО** | HTTP-проверки изучают HTML и сохранение данных, не исполняют JavaScript |
| Визуальная проверка / скриншоты | **НЕ ПРОВЕРЕНО** | В этом сеансе браузерная демонстрация не выполнялась |

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

Для завершения сдачи: выполнить браузерные шаги `DEMO-RU.md`, сохранить настоящие скриншоты по `SCREENSHOTS.md`; запустить и настроить SonarQube по `SONAR-SETUP.md`, просканировать обе версии, экспортировать и вручную разобрать Issues/Hotspots. Semgrep уже выполнялся ранее; повторный запуск не является частью этого исправления. Успех выбранных тестов не доказывает блокировку всех вариантов атак.
