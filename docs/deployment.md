# HoneyForge deployment

Одни и те же образы используются для локальной демонстрации и разнесённой
топологии. `deploy/docker-compose.yml` запускает Control Center,
`deploy/docker-compose.honeypots.yml` — Traps на том же или отдельном DMZ-хосте.

## Локальная CA

```bash
make env
make certs
```

Скрипт создаёт `deploy/nginx/certs/ca.crt` и подписанный им server certificate
для `localhost`, `assets.cdn-static.example` и `127.0.0.1`. CA certificate
монтируется Agent'ам read-only, поэтому его subject нейтрален
(`/CN=Local Demo CA`): атакующий с root на хосте ловушки прочитает этот файл.
CA private key никогда не монтируется в контейнеры. Повторный запуск сохраняет
существующие ключи; намеренная ротация:

```bash
bash deploy/scripts/gen_certs.sh --force
```

Ротация CA требует пересоздания агентов: после нового `--force` выполните
`make demo` (или перезапустите контейнеры ловушек), иначе агенты перестанут
проходить проверку сертификата.

TLS verification нельзя отключить: без `CENTER_CA_FILE` Agent использует
системное public-CA trust store, а с ним — указанный CA bundle. В обоих случаях
проверяются цепочка и hostname.

## Учётные записи операторов

`make env` (а внутри `make demo`) генерирует `OPERATOR_PASSWORD`, а также
опционального read-only оператора:

```dotenv
OPERATOR_USERNAME=operator
OPERATOR_PASSWORD=…
OPERATOR_ROLE=admin
OPERATOR_VIEWER_USERNAME=viewer
OPERATOR_VIEWER_PASSWORD=…
```

Центр заводит обоих при старте. Роль `viewer` умеет читать всё, но любая
изменяющая операция возвращает `403` и попадает в `audit_entries` как
`operator.access.denied`. Если viewer-пара не задана, центр работает с одним
администратором — это штатный режим. Половина заданных переменных (логин без
пароля или наоборот) приводит к отказу старта с внятной ошибкой.

## Сертификаты оператора и public CA

На Control Center задайте host paths в `.env`:

```dotenv
CENTER_TLS_CERT_FILE=/etc/honeyforge/tls/fullchain.pem
CENTER_TLS_KEY_FILE=/etc/honeyforge/tls/private.key
```

Для private CA на DMZ-хосте укажите bundle:

```dotenv
CENTER_CA_CERT_FILE=/etc/honeyforge/tls/operator-ca.pem
```

Для сертификата от public CA можно указать системный bundle хоста, например
`/etc/ssl/certs/ca-certificates.crt`. В собственном Compose override также
можно убрать mount `CENTER_CA_CERT_FILE` и оставить `CENTER_CA_FILE` пустым —
тогда Python использует системное trust store внутри образа.

## Proxy trust и сети

Только Nginx имеет адрес `172.30.0.10` во внутренней `mgmt_net`; API запускает
Uvicorn с `TRUSTED_PROXY_IPS=172.30.0.10`. Nginx перезаписывает входящие
`X-Forwarded-For` реальным peer address и удаляет `Forwarded`, поэтому клиент
не может подменить audit source IP. Если адрес внутреннего proxy меняется,
одновременно измените его static address и `TRUSTED_PROXY_IPS`; не указывайте
широкую публичную подсеть.

Agent подключён к двум сетям: `relay_egress_net` для исходящего management TLS
и `service_net` для эмулируемых портов. Он работает как
`syslog-relay`, с read-only root filesystem, dropped capabilities и
единственным persistent writable volume `/var/lib/syslog-relay`. В базовой
distributed-схеме `service_net` — internal network без внешнего маршрута;
каждый Agent слушает только свой статический адрес этой сети (`172.31.0.11` или
`172.31.0.12`), поэтому management-интерфейс не публикует trap-порты.

## Скрытность агента на хосте (MASK-4)

При старте агент переименовывает заголовок процесса, имя потока и командную
строку, поэтому в `ps` и в `/proc/<pid>/cmdline` он не читается как honeypot
агент. Псевдоним задаётся `PROCESS_MASK_NAME` (по умолчанию `syslog-relay`).
Значение с маркером `honey/agent/trap/decoy/c2` игнорируется в пользу дефолта,
поэтому маскировку нельзя случайно отключить неверной конфигурацией.

Канонический `setproctitle` используется, если он установлен (необязательный
extra `agent`: `pip install 'honeyforge[agent]'`); в противном случае работает
чисто-Python fallback (`prctl(PR_SET_NAME)` + перезапись argv), поэтому жёсткой
системной зависимости нет.

Для развёртывания вне Docker:

```bash
sudo LEVEL=low ./agent/install.sh   # LEVEL=low|medium
sudo systemctl start syslog-relay
```

Скрипт кладёт код в нейтральный каталог `/usr/lib/syslog-relay`, конфиг в
`/etc/syslog-relay/relay.env`, буфер в `/var/lib/syslog-relay`, создаёт
одноимённую системную учётную запись и юнит `syslog-relay.service` с
hardened-настройками (`ProtectSystem=strict`, `NoNewPrivileges`,
`ReadWritePaths` только на state-dir). Устанавливается единый пакет `relay.pyz` с нейтральными
именами модулей (`listeners`, `relay_common`, `http_service` и т. д.). `SERVICE_NAME`, `LEVEL`, `PYTHON` и пути
переопределяются переменными окружения; `SERVICE_NAME` с маркером скрипт
отклоняет.

В Docker и systemd используется один и тот же `relay.pyz`. Финальные образы
содержат пакет в `/usr/lib/syslog-relay/relay.pyz`, без деревьев `agent` и
`honeyforge_common`. Исходники в репозитории сохраняют доменные названия.
Сборка: `python3 agent/build_bundle.py --level low --output /tmp/relay.pyz`.
Для Medium укажите `--level medium`; интерпретатору нужна зависимость `asyncssh`.

Docker-сервисы называются `relay-a` и `relay-b`, контейнеры —
`syslog-relay-a` и `syslog-relay-b`, образы — `local/syslog-relay-a:dev` и
`local/syslog-relay-b:dev`. Используются volumes `relay_a_data`, `relay_b_data`
и сети `relay_egress_net`, `relay_service_net`. Ключ внутри контейнера:
`SERVICE_KEY_FILE=/run/secrets/relay.key`; CA — `/etc/syslog-relay/center-ca.crt`.
`LOW_TRAP_SECRET_FILE` / `MEDIUM_TRAP_SECRET_FILE` остаются параметрами выбора
исходного файла на машине оператора; исходный путь не устанавливается в контейнер.
Нейтральные имена не скрывают назначение от администратора с доступом к коду
или содержимому пакета.

### Обновление ранее установленной поставки

Повторный запуск `agent/install.sh` собирает новый пакет, убирает прежние
управляемые деревья Python-модулей и перезапускает службу. Существующий
`relay.env` и SQLite-буфер сохраняются; ключи `TRAP_SECRET_FILE` и
`AGENT_VERSION` в env-файле переводятся в `SERVICE_KEY_FILE` и `SERVICE_VERSION`.
Прежний стандартный файл `${CONFIG_DIR}/trap_secret` переименовывается в
`relay.key`, если новое имя свободно; конфигурация обновляется вместе с ним.
Пути к нестандартным ключам сохраняются.

В Docker сменились проект, имена контейнеров, сетей и volumes. Перед обновлением
остановите старую поставку её прежним Compose-файлом (`down` **без** `-v`),
чтобы освободить порты и подсеть `172.31.0.0/24`. Не удаляйте старые volumes:
они содержат очередь неподтверждённых событий. Скопируйте их в новые имена,
пока оба Agent остановлены:

```bash
docker volume create relay_a_data
docker volume create relay_b_data
# В типовой старой установке исходные имена приведены ниже; проверьте docker volume ls.
docker run --rm --user 0 -v honeyforge-honeypots_agent_low_data:/from:ro -v relay_a_data:/to python:3.12-slim python -c 'import shutil, os; shutil.copytree("/from", "/to", dirs_exist_ok=True); [os.chown(os.path.join(root, name), 10010, 10010) for root, dirs, files in os.walk("/to") for name in dirs + files]; os.chown("/to", 10010, 10010)'
docker run --rm --user 0 -v honeyforge-honeypots_medium_agent_data:/from:ro -v relay_b_data:/to python:3.12-slim python -c 'import shutil, os; shutil.copytree("/from", "/to", dirs_exist_ok=True); [os.chown(os.path.join(root, name), 10011, 10011) for root, dirs, files in os.walk("/to") for name in dirs + files]; os.chown("/to", 10011, 10011)'
```

После копирования запустите новую поставку с пересборкой образов. Для временного
использования прежних volumes доступны `RELAY_A_DATA_VOLUME` и
`RELAY_B_DATA_VOLUME`; они сохранят старые имена до отдельного переноса.
Не запускайте старый и новый контейнер одновременно на одной SQLite-очереди.

## Параметры агента

Помимо адреса центра и файлов ключа, агент читает:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `DELIVERY_INTERVAL_SECONDS` | `1` | Интервал доставки, если в профиле не задан `masking.beacon_interval_seconds` |
| `HEALTH_INTERVAL_SECONDS` | `30` | Период heartbeat'ов |
| `PROFILE_CHECK_INTERVAL_SECONDS` | `30` | Как часто агент забирает конфигурацию |
| `EVENT_QUEUE_MAX_EVENTS` / `EVENT_QUEUE_MAX_BYTES` | `100000` / `256 МиБ` | Пределы локальной очереди; переполнение уходит в карантин и отчёт о потерях |
| `PROCESS_MASK_NAME` | `syslog-relay` | Нейтральное имя процесса; значение с маркером игнорируется |
| `AGENT_VERSION` | `0.1.0` | Отчёт в Health Report |

**Каденция beacon'а не настраивается через окружение** — агент берёт
`masking.beacon_interval_seconds` и `masking.beacon_jitter_seconds` из профиля
ловушки; переменные `BEACON_*` в старых установках игнорируются и удалены из
манифестов.

## Запуск

### Полный локальный demo

На Linux x86-64 или arm64 с Docker Engine и Compose v2:

```bash
make demo          # центр + ловушки, идемпотентно
make demo-tour     # обход всех возможностей на живом стенде
make demo-smoke    # доказательство: события переживают обрыв связи
```

Внешние порты demo: Control Center `8443`; Low SSH/HTTP/MySQL `2222`, `8080`,
`33060`, UDP `9999/udp`; Medium SSH/HTTP/MySQL `2223`, `8081`, `33061`.
`make demo` безопасен для повторного запуска и не удаляет PostgreSQL volume.
Полный список команд — `make help` и [`README.md`](../README.md).

На Control Center:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
curl --cacert deploy/nginx/certs/ca.crt https://localhost/ready
```

На локальном хосте после создания Trap и записи выданного Trap Secret в файлы
из `.env`:

```bash
docker compose --env-file .env \
  -f deploy/docker-compose.honeypots.yml \
  -f deploy/docker-compose.demo.yml up -d --build
```

На отдельном DMZ-хосте overlay не используется:

```bash
docker compose --env-file .env -f deploy/docker-compose.honeypots.yml up -d --build
```

`AGENT_CENTER_URL` должен разрешаться в адрес Control Center. Локальный overlay
использует `host-gateway`; в distributed topology base manifest не задаёт
`extra_hosts`, поэтому используется обычный DNS.
Сторонний CDN не нужен: внешний `/assets/v2/*` завершается на Nginx и внутренне
proxy-передаётся FastAPI.

### Проверка перед сдачей

```bash
make honeypots-config              # манифест ловушок + demo-overlay валиден
make honeypots-distributed-config  # разнесённая топология валидна
make demo-status                   # ловушки в статусе online
make demo-masking                  # в артефакте агента нет слов про honeypot
make test-db                       # полный набор тестов против одноразовой БД
```

## Тесты

```bash
make test      # быстрый прогон без БД: PostgreSQL-тесты пропускаются
make test-db   # одноразовый postgres:16, полный набор, контейнер удаляется сам
```

`make test-db` занимает порт 55432; если он занят, команда подскажет конфликтующий
контейнер и примет другой порт: `make test-db TEST_DB_PORT=55433`.

## Одинаковая smoke-проверка обеих топологий

После enrollment выполните на машине с Python 3:

```bash
python3 deploy/scripts/smoke_deployment.py \
  --center-url https://assets.cdn-static.example \
  --ca-file deploy/nginx/certs/ca.crt \
  --trap-secret-file secrets/low_trap_secret
```

Probe проверяет `/ready`, затем отправляет один нормализованный Security Event
через `/assets/v2/init` и требует подтверждения его UUID. Для public CA параметр
`--ca-file` опускается. Секрет читается из файла и не появляется в argv или
выводе.

Nginx ограничивает Agent endpoint по размеру запроса, request rate и числу
соединений. Access logs используют JSON и записывают только `$uri` без query;
приложения дополнительно редактируют Bearer credentials, Enrollment Tokens,
Trap Secrets, JWT и пароли.


### Payload, fake-FS, UDP и fake-БД

Для существующего развёртывания сначала примените `alembic upgrade head`
в окружении Control Center, затем пересоберите образы Agent. Новые события
используют wire schema 2; события schema 1 продолжают приниматься.
Добавьте в Low Trap Profile сервис `udp` (например, порт 9999), а в Medium
Trap Profile — `mysql` (3306). Команда `make demo` создаёт эти сервисы и добавляет их в существующие demo-профили.
При ручной установке откройте соответствующие порты и установите обновлённые
модули через `agent/install.sh`.

Примеры проверки: `printf 'probe-payload' | nc -u -w 1 localhost 9999`,
`mysql --protocol=TCP --host=127.0.0.1 --port=33061 --user=admin -p`
(для demo пароль `Summer2026!`). В fake-БД: `SHOW DATABASES; USE app;
SHOW TABLES; SELECT * FROM users;`. В SSH: `cd /var/www/html`, `ls`,
`cat config.php`. В таблице событий доступны фильтры «Получен payload»
и «Запрос к БД»; payload хранится в JSON с base64-фрагментом и метаданными.
Это сбор ограниченного фрагмента, без отдельного хранилища полных файлов.
