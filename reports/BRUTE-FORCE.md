# Проверка входа и ограничения попыток

Используется обычная форма `/login`. Специальной страницы атаки или демонстрационного переключателя нет. Скрипт `tests/bruteforce.py` содержит ровно 10 паролей для учебного аккаунта alice, правильный — последний. Произвольные адреса и внешние словари скрипт не принимает.

## Что делает каждый вариант

| Адрес | Фактическое поведение | Механизм |
|---|---|---|
| localhost:8080 | 9 неправильных паролей без ограничений; на 10-й попытке вход | В уязвимом коде нет учёта ошибок |
| localhost:8081 | 429 с 6-й быстрой попытки; правильный пароль в этой серии также не принимается | nginx `limit_req`, 12 запросов/минуту, burst=4, nodelay |
| localhost:8082 | 429 начиная с 5-й ошибки; правильный пароль во время блокировки тоже получает 429 | Серверные счётчики ошибок в SQLite |

Это измеренные результаты короткой серии, не универсальные номера при любой скорости запросов. nginx ограничивает **частоту всех POST /login**, а приложение учитывает **неверные пароли**. Ограничение nginx не является правилом ModSecurity/CRS и не зависит от содержания пароля. `logs/login-rate.log` и `generated/nginx-login-evidence.json` подтверждают REJECTED в зоне portal_login; audit CRS сохранён отдельно в `logs/waf.log`.

На каждой попытке тест создаёт новую HTTP-сессию и меняет поддельные X-Forwarded-For/X-Real-IP. Защита сохраняется. Успех подтверждается одновременно `/api/me` (id=1, username=alice) и доступом к `/tickets` с личной заявкой Алисы; одного 200 или редиректа недостаточно. После ожидания 26 секунд обычный вход прошёл на обоих защищённых вариантах. Все результаты — `generated/bruteforce-{vulnerable,waf,fixed}.json` и `bruteforce-summary.json`.

## Настройки fixed и работа между процессами

В compose.yaml заданы LOGIN_MAX_FAILURES=5, LOGIN_WINDOW_SECONDS=60, LOGIN_BLOCK_SECONDS=15. Это короткие значения для воспроизводимой локальной демонстрации, а не рекомендация для эксплуатации в организации. Изменение требует пересоздания fixed. После изменения длительности ожидание демонстрационного скрипта может потребовать адаптации: оно ограничено 60 секундами.

`app-fixed/login_limits.py:authenticate` ведёт два независимых ограничения: по нормализованному имени аккаунта и по источнику. Они хранятся в таблице login_attempts в той же SQLite `/data/portal.db`, которая находится в постоянном томе fixed_data. Имя аккаунта в ключе хешируется. Учитывается `request.remote_addr`, а не присланные клиентом заголовки; ProxyFix не используется.

Транзакция BEGIN IMMEDIATE охватывает проверку состояния, проверку пароля и запись ошибки. Поэтому два процесса не смогут одновременно прочитать старое число ошибок и пропустить лишние попытки. WAL позволяет другим соединениям читать БД. Взамен проверка паролей сериализует писателей — это сознательный компромисс небольшого портала, не решение для высоконагруженного входа. При недоступности БД вход закрывается ответом 503, а не разрешается без счётчиков.

На пороговой ошибке и во время ограничения возвращаются 429, понятное сообщение и Retry-After. Повторные заблокированные запросы не продлевают срок. После его окончания счётчик начинает новый цикл. Успешный вход очищает счётчик аккаунта, но не счётчик источника: иначе владелец одного аккаунта мог бы сбрасывать защиту от перебора остальных. Истёкшие записи очищаются при попытках входа.

Несуществующий аккаунт получает тот же текст/статусы/порог и проходит проверку фиктивного хеша тем же алгоритмом. Это не обещание математически постоянного времени ответа. Общий IP за NAT разделяет один бюджет, а аккаунт может быть временно заблокирован чужими запросами: эти ограничения отдельно учитываются при проектировании реальной системы.

`tests/login_limit_checks.py`: 9 успешных тестов, включая новые сессии, поддельные заголовки, существующий/несуществующий аккаунт, истечение окна/блокировки, новый экземпляр приложения, CLI-сброс и отказ БД. Для каждого независимого бюджета проверены 12 запросов из 4 отдельных процессов: при лимите 5 ровно 4 ответа с обычной ошибкой и 8 ответов 429. Пороговый пятый запрос уже возвращает 429.

## Повторение на Windows

```powershell
.\scripts\lab.ps1 start
.\scripts\lab.ps1 brute-force
# Либо все HTTP, CRS, brute force и проверка журнала nginx:
.\scripts\lab.ps1 test
# Отдельный сброс перед ручной демонстрацией:
.\scripts\lab.ps1 reset-login-limits
```

`brute-force` автоматически пересобирает стенд, сбрасывает ограничения и запускает фиксированный список. `reset-login-limits` очищает только таблицу счётчиков fixed через Flask CLI и пересоздаёт WAF, очищая shared memory nginx. БД заявок и пользователей сохраняются. Reload nginx не используется для сброса: shared memory может переживать reload. Публичного HTTP-endpoint для сброса нет.

Для запуска Python-клиента непосредственно с хоста после сброса:

```powershell
.\.venv\Scripts\python.exe tests/bruteforce.py
.\.venv\Scripts\python.exe tests/login_limit_checks.py
```

## Docker на Linux/macOS

Те же образы и compose.yaml используются с Docker Compose v2. Для отдельного эксперимента Python на хосте не нужен:

```sh
docker compose up --build --force-recreate -d --wait
docker compose --profile checks build checks
docker compose exec -T fixed flask --app portal.main:create_app reset-login-limits
docker compose up -d --force-recreate --no-deps --wait waf
docker compose --profile checks run --rm --no-deps --entrypoint python checks bruteforce.py --inside-compose
docker compose logs --no-color --no-log-prefix waf > logs/login-rate.log
docker compose --profile checks run --rm --no-deps --entrypoint python checks check_login_logs.py
```

Основной прогон на трёх вариантах и CRS (выполнять перед brute force либо после сброса):

```sh
for mode in vulnerable waf fixed; do
  for service in vulnerable fixed; do
    docker compose exec -T "$service" flask --app portal.main:create_app clean-comments || exit 1
  done
  docker compose --profile checks run --rm checks --mode "$mode" || exit 1
done
for service in vulnerable fixed; do
  docker compose exec -T "$service" flask --app portal.main:create_app clean-comments || exit 1
  docker compose exec -T "$service" python - < tests/cleanup_check_data.py || exit 1
done
docker compose logs --no-color --no-log-prefix waf > logs/waf.log
docker compose --profile checks run --rm --no-deps --entrypoint python checks check_waf_logs.py
```

Эти shell-команды приведены для Docker на Linux/macOS; фактический управляющий прогон выполнен на Windows с Linux-контейнерами. Native macOS/Linux host-прогон отдельно не выполнялся.

Источники nginx: [limit_req, burst, пустой ключ и shared memory](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html), [realip_remote_addr — исходный адрес соединения](https://nginx.org/en/docs/http/ngx_http_realip_module.html). Лимит использует исходный TCP peer независимо от поддельного X-Forwarded-For.
