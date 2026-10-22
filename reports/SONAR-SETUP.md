# SonarQube Community Build: первый запуск

В проекте закреплена Community Build `26.10.0.133078-community`, отдельный PostgreSQL 17.9 и SonarScanner CLI Docker `12.2.0.4256_8.1.0`. Два проекта позволяют сравнивать версии без платного анализа веток.

## Текущее состояние стенда (22.10.2026)

Локальный сервер запущен и отвечает `UP` по `http://localhost:9000/api/system/status`. Первоначальная настройка выполнена `scripts/setup-sonar.py`: он проверил свежий вход `admin/admin`, заменил пароль случайным значением, записал его в игнорируемый `.runtime/sonar-admin-password.txt`, создал приватные проекты и сгенерировал токен в `.runtime/sonar-token.txt`. Срок этого токена — 7 дней; после истечения создайте новый в интерфейсе и замените локальный файл. Секреты не записаны в исходники, отчёты или логи.

Оба анализа уже успешно отправлены и экспортированы: vulnerable — 3 Issues, 0 Hotspots; fixed — 1 Issue, 0 Hotspots; quality gate для обоих — `OK`. Это реальные результаты текущего SonarQube Community Build, а не Semgrep. JSON-экспорты находятся в `reports/generated/sonar-*.json`; краткая оценка — в [TASK-2-SAST.md](TASK-2-SAST.md).

## Docker Compose и сохранение данных

SonarQube доступен только через `127.0.0.1:9000`. PostgreSQL не публикует порт. Compose хранит базу Sonar, загруженные анализаторы и журналы в отдельных именованных томах; остановка контейнеров не стирает анализы. Не запускайте `docker compose down -v`, если хотите их сохранить.

Windows PowerShell:

```powershell
.\scripts\lab.ps1 sonar
```

Linux/macOS с Docker Compose v2:

```sh
docker compose --profile analysis up -d --wait --wait-timeout 660 sonarqube
docker compose --profile analysis ps
```

Первый старт может занять несколько минут. Убедитесь, что `sonarqube` имеет статус `healthy`, а `http://localhost:9000/api/system/status` показывает `UP`.

## Первый вход, проекты и локальный токен

Первый запуск на чистой копии можно выполнить автоматически:

```powershell
.\scripts\lab.ps1 sonar
python scripts/setup-sonar.py --initialize-default-admin
```

Флаг разрешает скрипту принять только начальные `admin/admin`; при уже изменённом пароле он остановится, не пытаясь сбрасывать существующую учётную запись. Пароль и токен сохраняются в игнорируемых локальных файлах `.runtime/sonar-admin-password.txt` и `.runtime/sonar-token.txt`. Откройте `http://localhost:9000`, чтобы войти как `admin`: прочитайте локальный пароль из файла через свой менеджер/средство секретов. Скрипт создаёт приватные проекты `nexus-vulnerable` (`NEXUS - Vulnerable`) и `nexus-fixed` (`NEXUS - Fixed`) и отдельный токен анализа. Для повторного анализа запускать инициализатор не нужно.

Если автоматический инициализатор недоступен: на свежем сервере войдите `admin/admin`, смените пароль, в My Projects создайте те же два проекта, затем в My Account → Security создайте user token с правами анализа для обоих проектов. Скопируйте его сразу: SonarQube показывает значение один раз. Передайте токен только в переменную окружения текущего процесса либо в `.runtime/sonar-token.txt` (игнорируется Git). Не записывайте его в properties, исходники, отчёты или журналы.

Загрузка из локального файла в environment PowerShell, без вывода секрета:

```powershell
$line = Get-Content -LiteralPath .env.sonar -Raw
if ($line -notmatch '^SONAR_TOKEN=(.+)\s*$') { throw 'Ожидалась строка SONAR_TOKEN=...' }
$env:SONAR_TOKEN = $Matches[1].Trim()
try { .\scripts\lab.ps1 scan-sonar }
finally { Remove-Item Env:\SONAR_TOKEN -ErrorAction SilentlyContinue; Remove-Variable line }
```

Или задайте переменную в текущем окне PowerShell скрытым вводом:

```powershell
$secure = Read-Host 'SonarQube token' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:SONAR_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); Remove-Variable secure,ptr }
try { .\scripts\lab.ps1 scan-sonar }
finally { Remove-Item Env:\SONAR_TOKEN -ErrorAction SilentlyContinue }
```

`scripts/lab.ps1 scan-sonar` также может прочитать одну строку `SONAR_TOKEN=...` из исключённого из Git файла `.runtime/sonar-token.txt`. Значение не выводится в консоль и не передаётся параметром командной строки. Docker-владелец локального компьютера может прочитать environment запущенного scanner-контейнера, поэтому не используйте общую недоверенную машину.

## Два анализа и сохранённые результаты

Проекты используют `sast/sonar-vulnerable.properties` и `sast/sonar-fixed.properties`. Каждый задаёт свой ключ, имя и корень исходников (`app/` и `app-fixed/`). Сканер отправляет результаты раздельно; экспорт дожидается завершения анализа и отдельно сохраняет Issues, Security Hotspots и quality gate.

```powershell
.\scripts\lab.ps1 scan-sonar
```

Результаты появятся как `reports/generated/sonar-vulnerable-*.json` и `sonar-fixed-*.json`. Сравнивайте их с исходными хешами и находками Semgrep в `sast-before-bruteforce/` и `sast-after-bruteforce/`. Сохранённые результаты Semgrep сами по себе не означают, что SonarQube уже сканировал проект.

## Если Elasticsearch требует настройки Linux VM

SonarQube использует Elasticsearch. По [официальным требованиям](https://docs.sonarsource.com/sonarqube-community-build/server-installation/pre-installation/linux) Linux-хост должен иметь `vm.max_map_count >= 524288`, `fs.file-max >= 131072`; нужны также ограничения открытых файлов и потоков. В Compose уже заданы ulimits контейнера; sysctl Linux VM автоматически не меняется.

Только если Docker Desktop использует уже установленный WSL 2 backend и ошибка действительно указывает на эти значения, проверьте их вручную:

```powershell
wsl -d docker-desktop -- sysctl vm.max_map_count fs.file-max
```

Если значения меньше требуемых, администратор машины может **самостоятельно** применить временные изменения в VM:

```powershell
wsl -d docker-desktop -u root -- sysctl -w vm.max_map_count=524288
wsl -d docker-desktop -u root -- sysctl -w fs.file-max=131072
.\scripts\lab.ps1 sonar
```

Эти команды не выполнялись при создании проекта. Они могут не подходить для Hyper-V backend или другой версии Docker Desktop. Не устанавливайте WSL только ради обхода ошибки без выбора подходящего backend по официальной инструкции. Не отключайте Elasticsearch bootstrap checks, чтобы скрыть несоответствие требований. Временные значения могут сброситься при перезапуске VM.

## Что означает результат

- **Подтверждённая уязвимость:** ручной анализ потока и воспроизведение показывают нарушение свойства безопасности.
- **Security Hotspot:** чувствительный участок, требующий проверки контекста; это не доказанная эксплуатация.
- **Замечание качества:** читаемость, сложность, дублирование и т. п.; не следует автоматически называть его уязвимостью.

Community Build — бесплатный локальный вариант; не обещаем коммерческий taint analysis и обнаружение всех инъекций. Возможности сверяются с [официальным сравнением](https://docs.sonarsource.com/sonarqube-community-build/feature-comparison-table) и [репозиторием SonarQube](https://github.com/SonarSource/sonarqube). Настройки сканера: [официальная документация CLI](https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner).

При написании автоматического экспорта использовалась [официальная документация Web API Community Build](https://docs.sonarsource.com/sonarqube-community-build/extension-guide/web-api), включая API-токен для аутентификации.
