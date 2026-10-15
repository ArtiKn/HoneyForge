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
монтируется Agent'ам read-only. CA private key никогда не монтируется в
контейнеры. Повторный запуск сохраняет существующие ключи; намеренная ротация:

```bash
bash deploy/scripts/gen_certs.sh --force
```

TLS verification нельзя отключить: без `CENTER_CA_FILE` Agent использует
системное public-CA trust store, а с ним — указанный CA bundle. В обоих случаях
проверяются цепочка и hostname.

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

Agent подключён к двум сетям: `agent_egress_net` для исходящего management TLS
и `honeypot_exposed` для эмулируемых портов. Он работает как
`honeyforge-agent`, с read-only root filesystem, dropped capabilities и
единственным persistent writable volume `/var/lib/honeyforge`. В базовой
distributed-схеме `honeypot_exposed` — internal network без внешнего маршрута;
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
`ReadWritePaths` только на state-dir). Файл точек входа копируется под
нейтральным именем `relay.py`. `SERVICE_NAME`, `LEVEL`, `PYTHON` и пути
переопределяются переменными окружения; `SERVICE_NAME` с маркером скрипт
отклоняет.

Маскируется то, что видно в списке процессов: заголовок, поток, cmdline и имя
сервиса. Имена кодовых пакетов (`honeyforge_common`, `agent`) — идентификаторы
исходников, они не выводятся в `ps`.

## Запуск

### Полный локальный demo

На Linux x86-64 или arm64 с Docker Engine и Compose v2:

```bash
make demo
make demo-attack
make demo-smoke
```

Внешние порты demo: Control Center `8443`; Low SSH/HTTP/MySQL `2222`, `8080`,
`33060`; Medium SSH/HTTP `2223`, `8081`. `make demo` безопасен для повторного
запуска и не удаляет PostgreSQL volume.

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

## Одинаковая smoke-проверка обеих топологий

После enrollment выполните на машине с Python 3:

```bash
python3 deploy/scripts/smoke_deployment.py \
  --center-url https://assets.cdn-static.example \
  --ca-file deploy/nginx/certs/ca.crt \
  --trap-secret-file deploy/secrets/low_trap_secret
```

Probe проверяет `/ready`, затем отправляет один нормализованный Security Event
через `/assets/v2/init` и требует подтверждения его UUID. Для public CA параметр
`--ca-file` опускается. Секрет читается из файла и не появляется в argv или
выводе.

Nginx ограничивает Agent endpoint по размеру запроса, request rate и числу
соединений. Access logs используют JSON и записывают только `$uri` без query;
приложения дополнительно редактируют Bearer credentials, Enrollment Tokens,
Trap Secrets, JWT и пароли.
