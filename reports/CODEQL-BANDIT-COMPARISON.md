# Сравнение локальных CodeQL и Bandit

Последний повторный анализ после изменения лимитера 23.10.2026: `generated/codeql-sast/fixed-20261023-144536/`, CodeQL 0, Bandit 2 Low (B404/B603), прежние версии и официальный набор. Подробности: [LOGIN-POLICY-20261023.md](LOGIN-POLICY-20261023.md). Предыдущие результаты ниже сохранены.

## Текущий результат: каталог документов fixed, 22 октября 2026

После новой доработки **CodeQL: 0 результатов**, **Bandit: 2 предупреждения Low / High confidence**. Это новый реальный запуск по изменённому коду, а не изменение SARIF или статуса старых находок. Уязвимое приложение `app/` не менялось. Все предыдущие SARIF/JSON, включая пользовательский запуск `fixed-20261022-232717`, сохранены.

| Этап | CodeQL | Bandit | Свидетельство |
|---|---|---|---|
| Vulnerable, ранее сохранённый анализ | 4: SQLi, command injection, 2 path injection | 4: B608, B604, B404, B602 | [Предыдущая сводка](generated/codeql-sast/vulnerable-20261022-224555/summary.json); в этой доработке повторно не сканировался |
| Fixed непосредственно до доработки | 3 × `py/path-injection`, `main.py:204,208,210` | 2: B404, B602 | [Сводка до изменения](generated/codeql-sast/fixed-20261022-232717/summary.json), [исходный SARIF](generated/codeql-sast/fixed-20261022-232717/codeql.sarif) |
| Fixed после доработки | **0** | **2: B404, B603** | [Новая сводка](generated/codeql-sast/fixed-20261022-234453/summary.json), [SARIF](generated/codeql-sast/fixed-20261022-234453/codeql.sarif), [Bandit JSON](generated/codeql-sast/fixed-20261022-234453/bandit.json) |

### Что изменено и почему

1. В [`app-fixed/main.py:18`](../app-fixed/main.py#L18) `DOCUMENTS` теперь хранит для каждого публичного идентификатора заголовок и **заранее заданный сервером Path**. Названия `onboarding.txt`, `vpn.txt`, `meetings.txt` остались совместимыми идентификаторами существующих ссылок. Контекст шаблонов получает заголовки из этого же каталога; независимого второго списка разрешённых файлов нет. Шаблоны менять не потребовалось.
2. В [`download():207`](../app-fixed/main.py#L207) пользовательское значение выбирает запись через `DOCUMENTS.get(...)`; оно больше не участвует в конструировании или нормализации пути. Неизвестные ID, включая пустую строку, `./onboarding.txt`, traversal и абсолютные пути даже к разрешённому документу, дают **400**. Отсутствующий на диске известный файл даёт 404. Без параметра сохранён onboarding; обычный ответ — inline, `attachment=1` — attachment. Устранён сам поток «HTTP → конструирование пути», который отмечал CodeQL; проверки и опасные операции не спрятаны от анализатора.
3. В [`app-fixed/process.py:12`](../app-fixed/process.py#L12) удалён параметр `shell` из API helper; в `subprocess.Popen` теперь непосредственно записано `shell=False`. Единственный вызывающий маршрут передаёт список аргументов. Это новая доработка ограничения возможностей helper; проверка IP/loopback уже существовала до текущей работы. Ограничения времени, объёма вывода и завершение процесса сохранены.

| Оставшийся сигнал Bandit | Причина и проверенный поток | Решение |
|---|---|---|
| `B404`, Low / High, `app-fixed/process.py:4` | Импорт стандартного `subprocess` нужен для настоящего ping. Сам импорт не является выполнением пользовательской команды. | Оставлен в исходном JSON без `nosec` и исключений. |
| `B603`, Low / High, `app-fixed/process.py:14` | `request.form['host']` → `ipaddress.ip_address` → проверка `is_loopback` → каноническая строка IP → список аргументов ping → `Popen(shell=False)`. Исполняемая программа и ключи задаются сервером. Локальные тесты подтвердили отклонение командных операторов и успешный ping. Helper отдельно проверен с метасимволами как буквальным аргументом. | Для текущего маршрута command injection не подтверждён. Общий сигнал о необходимости проверить вход subprocess сохранён. Это не доказательство безопасности будущих вызовов helper; доверие к системному PATH/образу остаётся предпосылкой. |

Прежний `B602` High исчез благодаря удалению возможности включать shell, а не снижению серьёзности правила. Число предупреждений Bandit осталось 2, но состав изменился: B602 заменился общим B603. Ноль CodeQL не означает отсутствие всех возможных уязвимостей.

### Повторные проверки и охват

- **37/37** тестов Flask/SQLite и реальных локальных процессов: [summary.json](generated/codeql-sast/catalog-checks-20261022-234451/summary.json), [подробный журнал](generated/codeql-sast/catalog-checks-20261022-234451/tests.log). Добавлены проверки полного каталога, ссылок обеих страниц, содержимого всех трёх документов, inline/attachment, отсутствующего параметра, отказа для неразрешённых ID и путей, сохранения авторизации, таймаута и ограничения вывода fixed helper. Сюда входят прежние проверки vulnerable на временной базе; её исходники не менялись.
- Контейнер **только fixed** пересобран и запущен в healthy. Прямой адрес **http://127.0.0.1:8082**, без WAF: **24/24** существующих HTTP-регрессий ([отчёт](generated/codeql-sast/catalog-checks-20261022-234451/http-fixed.json)), включая нормальный ping, traversal и command injection; отдельно **35/35** проверок всех ссылок документов и отказов ([отчёт](generated/codeql-sast/catalog-checks-20261022-234451/documents-http.json)).
- `scripts/verify-project.py` завершился с кодом 0. Конфигурация Docker/WAF, non-root и ограничения контейнеров не менялись.
- CodeQL **2.27.2**, официальный `codeql/python-queries` **1.8.12**, неизменённый `python-security-extended.qls`, **52/52** запроса. База fixed пересоздана из текущих исходников, отчёт записан в новую папку. Bandit **1.9.4**, все стандартные проверки со всеми уровнями severity/confidence. Скрипт сканирования и lock-файл не изменялись; новых исключений файлов, строк или правил нет.
- Все **5 Python-файлов** fixed присутствуют в инвентаре, CodeQL baseline/source archive и метриках Bandit: `__init__.py`, `db.py`, `login_limits.py`, `main.py`, `process.py`. CodeQL invocation errors — 0, Bandit parse errors — 0, подавлений `nosec` — 0. [Инвентарь](generated/codeql-sast/fixed-20261022-234453/source-inventory.json) также содержит 17 непитоновских файлов и 5 `.pyc`. В baseline CodeQL дополнительно перечислены встроенные фрагменты из двух HTML-шаблонов; запуск Python suite не является полным анализом HTML/JavaScript/CSS.
- В новом логе создания базы снова есть **4** сообщения `No installed Python found!` вспомогательного Windows launcher. База успешно создана; все Python-файлы и запросы учтены. Эти сообщения нельзя выдавать за ошибки разбора исходников, но полнота автоматического обнаружения зависимостей не подтверждена. В пользовательском запуске 23:27 сводка содержала 0 таких сообщений; здесь приведены именно новые фактические данные.
- WAF, браузерное исполнение XSS, SonarQube и Semgrep заново не запускались. Их прежние отчёты не изменялись. Полная команда `lab.ps1 test` не запускалась: повторены соответствующие fixed HTTP-тесты и расширенные тесты документов.
- HTTP-регрессии создают учебную заявку и комментарии. Первоначально автоматическая проверка отклонила стандартный `clean-comments`, поскольку он заменяет все комментарии заявки 1003, в том числе потенциально пользовательские. После отдельного явного разрешения пользователя очистка выполнена **только в fixed**: восстановлены два стандартных комментария заявки 1003, скриптом `tests/cleanup_check_data.py` удалена неизменённая тестовая заявка **1013**. Последующая проверка БД подтвердила точное содержимое обоих стандартных комментариев и отсутствие заявки 1013, её комментариев и участников. Vulnerable не затронут; исходные результаты сканирования и тестов сохранены.

Повторить новый анализ и отдельную проверку документов из корня проекта:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local-sast.ps1 fixed -RecreateDatabase
$checkStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
.\.venv\Scripts\python.exe tests/document_catalog_checks.py --base http://127.0.0.1:8082 --report "reports/generated/documents-$checkStamp.json"
.\.venv\Scripts\python.exe -m unittest discover -s tests -p unit_checks.py -v
```

Последняя команда запускает локальные проверки, включая обе версии на временных БД, без перезаписи старого `local-checks.json`. HTTP-проверка требует работающего обновлённого fixed. Скрипт документов не перезаписывает существующий файл отчёта. Все данные остаются локально.

Дополнительные свидетельства: [охват, метрики и SHA-256 исходников](generated/codeql-sast/fixed-20261022-234453/coverage-evidence.json), [diff реализации и регрессионных тестов](generated/codeql-sast/fixed-20261022-234453/implementation.patch). Все пять файлов fixed побайтово сверены с `src.zip` новой CodeQL-базы. Хеши исходников и ресурсов vulnerable до и после работы совпали. Локальная копия fixed до изменения сохранена в `.runtime/fixed-catalog-before-20261022-234409/`.

## Предыдущая серия запусков — исторический результат до изменения реализации

Ниже сохранён разбор первоначальных результатов. Указанные там 3 предупреждения CodeQL fixed и B602 относятся к **старому коду**; актуальные результаты и изменения перечислены выше.

Для учебного SAST-сравнения установлены CodeQL CLI **2.27.2** из официального Windows bundle и Bandit **1.9.4**. CodeQL использовал неизменённый официальный набор `codeql/python-queries` **1.8.12**, suite `python-security-extended.qls`; контрольная сумма bundle закреплена в [`sast/codeql-lock.json`](../sast/codeql-lock.json). Для Bandit закреплены версия программы и зависимости в [`sast/requirements-sast.txt`](../sast/requirements-sast.txt). Это анализ Python-части двух приложений, а не всего сайта.

Обе версии сканировались тем же PowerShell wrapper, набором CodeQL-запросов и параметрами Bandit. Не применялись собственные CodeQL-запросы, исключения файлов, Bandit-профиль или `# nosec`. CodeQL выполнил 52/52 запросов в каждой базе; ошибок CodeQL invocation — 0. Bandit записал JSON со всеми серьёзностями и уровнями уверенности; ошибок разбора — 0, пропущенных проверок — 0. Код не отправлялся в SonarQube/GitHub или иной облачный сканер.

Финальные результаты созданы 22 октября 2026 года:

| Версия | Файлы в каталоге | Python-файлы CodeQL и Bandit | CodeQL SARIF | Bandit JSON | Ошибки | Нефатальный notice launcher |
|---|---:|---:|---:|---:|---:|---:|
| `app/` vulnerable | 25 | 4 | 4 результата | 4 результата | 0 | 4 |
| `app-fixed/` fixed | 27 | 5 | 3 результата | 2 результата | 0 | 4 |

Файлы результатов:

- vulnerable: [`codeql.sarif`](generated/codeql-sast/vulnerable-20261022-224555/codeql.sarif), [`bandit.json`](generated/codeql-sast/vulnerable-20261022-224555/bandit.json), [сводка и инвентарь](generated/codeql-sast/vulnerable-20261022-224555/summary.json);
- fixed: [`codeql.sarif`](generated/codeql-sast/fixed-20261022-224644/codeql.sarif), [`bandit.json`](generated/codeql-sast/fixed-20261022-224644/bandit.json), [сводка и инвентарь](generated/codeql-sast/fixed-20261022-224644/summary.json);
- обе базы CodeQL хранятся локально и отдельно в `.runtime/codeql/databases/vulnerable` и `.runtime/codeql/databases/fixed` (каталог исключён из Git);
- безопасное локальное воспроизведение Flask/SQLite и процессов: [reproduction-checks.json](generated/codeql-sast/reproduction-checks.json), **34/34 теста пройдены**.

Первоначальные попытки запуска оставили диагностические логи в отдельных timestamp-каталогах. Их не включали в приведённые числа. Успешные запуски выше сделаны окончательным wrapper; он фиксирует версии, создаёт самостоятельную базу, сохраняет логи и результаты в новой timestamp-папке.

## Охват и ограничения

CodeQL и Bandit обошли все исходные `.py` файлы внутри каждой заданной папки:

- `app/`: `__init__.py`, `db.py`, `main.py`, `process.py`;
- `app-fixed/`: `__init__.py`, `db.py`, `login_limits.py`, `main.py`, `process.py`.

В каждой папке также обнаружено 17 непитоновских исходников и ресурсов: 12 Jinja/HTML-шаблонов, `static/portal.css` и 4 текстовых файла. Кроме того, в инвентаре видны 4/5 сгенерированных `.pyc` файлов из `__pycache__`; это байткод, его анализаторы не считают исходным Python-кодом. Подробный список файлов каждого запуска находится в `source-inventory.json`. JavaScript-файлов в этих двух каталогах нет.

Обе программы запускались без фильтрации `.py` файлов. CodeQL анализировал язык Python; Bandit рекурсивно обходил только соответствующее приложение. HTML-шаблоны, CSS и текстовые документы не проверялись CodeQL Python/Bandit и не включены в их счётчики. Поэтому результат нельзя называть анализом всего портала. Для шаблонов в проекте уже сохранены отдельные результаты Semgrep с учебными правилами, а SonarQube ранее находил небезопасные `|safe` в vulnerable-шаблонах. Проверка выполнения XSS в браузере в этом запуске не проводилась.

На этой Windows-машине `py -0p` сообщает, что установленных Python нет, хотя `python.exe` доступен напрямую и виртуальное окружение проекта исправно. Поэтому Python extractor явно использовал `--extractor-option=python.python_executable_name=python`. В логах создания каждой базы всё же есть по четыре сообщения `No installed Python found!`: вспомогательный `python_setup.cmd` bundle вызывает `py` для необязательного определения/установки зависимостей и терпимо завершает эту часть при нерабочем launcher. Это **ограничение анализа зависимостей**, а не успешный тест их обнаружения. При этом обе базы завершились сообщением `Successfully created database`, SARIF содержит 0 invocation errors, а логи показывают выполнение всех 52 запросов. CodeQL проиндексировал исходные Python-файлы; анализ зависимости от установленных библиотек мог быть неполным. Приложения не собирались и не запускались для создания баз; внутренний `autobuild.cmd` — скрипт Python extractor, а не сборка приложения. Локальная PowerShell запрещала запуск скриптов, поэтому использован временный `-ExecutionPolicy Bypass` для процесса `powershell.exe`; глобальная Execution Policy не менялась.

## Находки, проверка и исправления

Исправления в `app-fixed/` существовали до этой серии CodeQL/Bandit запусков; в рамках неё файлы приложений не менялись. Уязвимости в `app/` намеренно сохранены. Автоматическое предупреждение не считалось доказательством само по себе: сравнение ниже учитывает фактический поток и тесты.

| Проблема и scanner finding | Поток/причина в vulnerable | Fixed и повторный анализ | Проверка и статус |
|---|---|---|---|
| SQL injection — CodeQL `py/sql-injection` (security severity 8.8), `app/main.py:164`; Bandit `B608` Medium / Low confidence, `app/main.py:162` | `request.args['q']` (`main.py:160`) встраивается в f-string SQL (`:162`), затем исполняется через `execute(sql)` (`:164`). CodeQL SARIF содержит путь источник → `query` → SQL-строка → `execute`. | Уже исправлено до сканирования: `app-fixed/main.py:182-184` передаёт шаблон отдельно от параметра `f'%{query}%'`. После исправления ни `py/sql-injection`, ни `B608` нет. | Изолированный тест подтверждает изменение выборки на учебных строках в vulnerable и отсутствие обхода в fixed. Уязвимость подтверждена в vulnerable, исправление подтверждено тестом и исчезновением обоих предупреждений. |
| Command injection — CodeQL `py/command-line-injection` (9.8), `app/process.py:14`; Bandit `B604` Medium / Low confidence (`app/main.py:196`) и `B602` High / High confidence (`app/process.py:14`) | POST `/diagnostics`: пользовательское поле `host` (`app/main.py:192`) соединяется в строку команды (`:195`), вызывается `bounded_run(..., shell=True)` (`:196`), далее `Popen` (`app/process.py:14`). SARIF показывает этот путь. | Уже исправлено: `app-fixed/main.py:216-224` разбирает IP, разрешает только loopback и передаёт список аргументов с `shell=False`. CodeQL command injection и Bandit `B604` исчезли. | Тест с безвредным `echo LAB_TEST` подтверждает исполнение команды vulnerable и отказ fixed. В fixed остаётся Bandit `B602` на общем helper `app-fixed/process.py:12-15`: статическая эвристика видит параметр `shell=shell`, но единственный вызов маршрута явно передаёт `shell=False` и аргументы-массив (`app-fixed/main.py:224`). Это не воспроизвелось как проблема в текущем маршруте; предупреждение сохранено, не подавлено. `B404` (Low / High confidence) в обеих версиях лишь отмечает импорт модуля `subprocess`, сам по себе не подтверждает уязвимость. |
| Path traversal — CodeQL `py/path-injection` (7.5), два результата `app/main.py:184` и `:186` | Параметр `file` попадает в `ROOT / 'documents' / input` (`:183`), затем проверяется `.is_file()` и передаётся `send_file()`. CodeQL SARIF показывает путь запроса к проверке/отправке файла. | Уязвимость была исправлена заранее: `app-fixed/main.py:202-210` разрешает канонический путь, требует `target.relative_to(directory)` и прекращает запрос через `abort(400)`, если цель вышла из каталога. CodeQL всё ещё выдаёт три `py/path-injection` на `:204`, `:208`, `:210`, поскольку видит, что путь зависит от запроса, но не учитывает проверку containment и ветку abort как достаточную защиту. | Тесты с `../lab-only.txt`, альтернативной нормализацией и абсолютным путём: vulnerable возвращает маркер из учебного файла, fixed возвращает 400 и не выдаёт файл. Для текущей модели приложения это ложное срабатывание CodeQL, а не сохраняющаяся эксплуатационная проблема. Предупреждения оставлены в SARIF и не исключены. Смена файлов/ссылок на диске параллельным локальным атакующим отдельно не моделировалась. |

Итоговое сопоставление результатов: SQLi и command injection были и автоматически отмечены в vulnerable, исправлены ранее, в fixed больше не отмечаются соответствующими CodeQL/Bandit правилами. Path traversal отмечен CodeQL в обеих версиях, но fixed-защита подтвердилась отдельным локальным тестом. В fixed Bandit сохраняет общий `B404` и `B602`; они описаны выше без сокрытия из отчёта.

## Что эти правила пропустили

CodeQL и Bandit в этой конфигурации не дали находок для ряда известных сценариев:

- Reflected и Stored XSS: Python-анализ не проверяет сами Jinja/HTML-шаблоны в выбранном запуске; в них vulnerable-версия использует `|safe`, а fixed-версия вернула автоэкранирование. В прежнем SonarQube-экспорте `Web:S5247` открыт на `greeting.html` и `ticket.html` только в vulnerable и отсутствует в fixed. Прежние custom Semgrep-правила также указывали на шаблоны. Текущий CodeQL/Bandit запуск не выполнял браузерный JavaScript тест.
- IDOR: не обнаружен этими статическими анализаторами. Проверка требует понимания владельца/участника заявки: изолированный набор проверил чтение/запись между Alice и Bob; vulnerable даёт доступ, fixed блокирует чужую заявку. CodeQL и Bandit не заменяют анализ этой модели доступа.
- Ограничение перебора паролей: CodeQL/Bandit не доказывают наличие или отсутствие рабочей rate-limit политики. В `app-fixed/login_limits.py` она уже была до сканирования; отдельные прежние тесты ограничений входа лежат в `generated/login-limit-checks.json`. Эти тесты не запускались повторно в рамках CodeQL/Bandit прохода.
- CSRF: CodeQL/Bandit не подтвердили её автоматически. SonarQube S4502 ранее помечен `FALSE-POSITIVE` в обеих версиях после проверки собственной защиты; прежний прямой набор CSRF-тестов — `generated/csrf-checks.json` — прошёл 17/17. В этом запуске он отдельно не повторялся.

Последние сохранённые анализы SonarQube и Semgrep в этой работе не перезапускались и не изменялись. В последнем SonarQube-экспорте vulnerable имеет два открытых `Web:S5247` на шаблоны и разрешённый как false positive `python:S4502`; fixed имеет только разрешённый `python:S4502`. Сохранённые Semgrep результаты показывают ноль в Registry-наборе для обоих вариантов; предыдущие custom-правила отмечали SQLi/XSS/command/path в vulnerable и оставляли одно path-предупреждение в fixed. Подробности и первоначальные результаты остаются в [`TASK-2-SAST.md`](TASK-2-SAST.md) и исходных папках отчётов; их здесь не перезаписывали.

Сетевой WAF не участвовал в SAST-сканировании и не может исправить код. Ранее сохранённое тестирование WAF блокировало вредоносные SQLi, XSS, command и traversal запросы; IDOR проходит через WAF, потому что решение требует проверки пользователя и объекта в приложении. В этом запуске WAF не тестировался повторно.

## Повторить сканирование в Windows PowerShell

В этом workspace CodeQL bundle распакован в игнорируемый `.runtime/tools/codeql-bundle-v2.27.2`, а Bandit установлен в локальный `.venv`. При новом checkout `.runtime` не попадёт из Git, поэтому если CodeQL ещё не распакован, скачай официальный bundle и проверь зафиксированный SHA-256:

```powershell
$sastTools = Join-Path $PWD '.runtime/tools'
$codeqlArchive = Join-Path $sastTools 'codeql-bundle-win64-v2.27.2.tar.gz'
New-Item -ItemType Directory -Force -Path $sastTools | Out-Null
Invoke-WebRequest 'https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.2/codeql-bundle-win64.tar.gz' -OutFile $codeqlArchive
$expectedSha256 = 'c4834b337e2db85bdd4e7e97455319ff70d28f06abb2987eff9ec0f62d51dcea'
if ((Get-FileHash $codeqlArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSha256) { throw 'CodeQL bundle SHA-256 mismatch' }
$codeqlHome = Join-Path $sastTools 'codeql-bundle-v2.27.2'
New-Item -ItemType Directory -Force -Path $codeqlHome | Out-Null
tar.exe -xzf $codeqlArchive -C $codeqlHome
```

Если Bandit ещё не установлен:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\sast\requirements-sast.txt
```

Затем запусти vulnerable, открой его SARIF/JSON и изучи находки. Только после этого запусти fixed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local-sast.ps1 vulnerable -RecreateDatabase
# Скрипт напечатает новую папку reports/generated/codeql-sast/vulnerable-<timestamp>.
# Просмотри codeql.sarif и bandit.json.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local-sast.ps1 fixed -RecreateDatabase
# Просмотри codeql.sarif и bandit.json fixed-версии.
```

`-RecreateDatabase` удаляет и пересоздаёт только соответствующую CodeQL-базу внутри `.runtime/codeql/databases`; отчёт получает новую timestamp-папку. Скрипт проверяет CLI/query pack версии и пишет создание базы, анализ, инвентарь, JSON и SARIF. Bandit может вернуть код 1 из-за найденных проблем; это не ошибка запуска. Технические ошибки отдельно подсчитываются по JSON/SARIF.

Чтобы открыть CodeQL SARIF в VS Code, установи расширение **SARIF Viewer** (`MS-SarifVSCode.sarif-viewer`), открой папку `app/` как workspace для vulnerable (или `app-fixed/` для fixed), затем открой соответствующий `codeql.sarif` из папки `reports/generated/...` через **File → Open File**. В Results Panel выбери правило и кликни результат: расширение показывает путь данных и переводит к строке исходника. Сам анализ и отчёты остаются локальными. [Инструкция SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer). Marketplace указывает, что расширение собирает ограниченную анонимную телеметрию, в частности версии/схемы открытых журналов. Это не загрузка исходников; если нужна строгая работа без телеметрии расширений, не устанавливай его и просматривай SARIF/JSON как локальные файлы. VS Code описывает настройку телеметрии в [официальной документации](https://code.visualstudio.com/docs/configure/telemetry) и отдельно предупреждает, что отдельные расширения могут иметь собственную телеметрию.

Пакеты и документация: [официальный CodeQL CLI bundle](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli), [стандартные CodeQL query suites](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-query-suites), [Bandit JSON-формат](https://bandit.readthedocs.io/en/latest/formatters/json.html).
