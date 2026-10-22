# SonarQube Community Build: первый запуск

В проекте закреплена Community Build `26.10.0.133078-community`, отдельный PostgreSQL 17.9 и SonarScanner CLI Docker `12.2.0.4256_8.1.0`. Два проекта позволяют сравнивать версии без платного анализа веток.

## Запуск и первичная настройка

```powershell
.\scripts\lab.ps1 sonar
```

Откройте http://localhost:9000. При первом входе используйте стандартные `admin / admin`, затем **самостоятельно** задайте новый пароль администратора. Создайте два локальных проекта с ключами `nexus-vulnerable` и `nexus-fixed`. Оставьте профиль Python `Sonar way`; запишите в отчёт его фактическое название и версии анализаторов. Изменения профиля меняют результаты и требуют нового анализа.

В My Account → Security создайте ограниченный по сроку **user token** пользователя с Execute Analysis и Browse для обоих проектов. User token нужен также для чтения результатов API; project analysis token одного проекта может быть недостаточен. Не используйте настоящий рабочий токен — это отдельный локальный SonarQube.

Введите токен скрыто и сохраните только в переменной текущего процесса PowerShell:

```powershell
$secureSonarToken = Read-Host 'Local SonarQube token' -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSonarToken)
try {
    $env:SONAR_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    Remove-Variable secureSonarToken,tokenPointer
}
try {
    .\scripts\lab.ps1 scan-sonar
} finally {
    Remove-Item Env:\SONAR_TOKEN -ErrorAction SilentlyContinue
}
```

Не добавляйте токен в `.env`, properties, README, историю команд или скриншоты. Scanner получает его через environment. Локальный владелец Docker может видеть environment контейнеров — это доверенная машина лаборатории, не многопользовательский сервер.

Scanner сначала отправляет анализ, затем `export-sonar.ps1` ждёт SUCCESS фоновой задачи CE. Только после этого экспортируются issues, hotspots и quality gate. Непройденный quality gate у уязвимого проекта — возможный результат анализа, а не ошибка запуска сканера. FAILED/CANCELED задачи, ошибки HTTP и незавершённый экспорт дают FAIL.

Результаты сохраняются в `reports/generated/sonar-*-{issues,hotspots,qualitygate,task}.json`. После запуска заполните колонку SonarQube в `TASK-2-SAST.md` настоящими rule IDs, файлами, строками и статусами. Сейчас она **NOT RUN**, а не «ничего не найдено».

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
