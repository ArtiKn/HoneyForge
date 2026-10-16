# HoneyForge

> Конструктор и центр управления реалистичными ловушками-приманками.  
> Кейс III Межрегионального хакатона **UmirHack**.

Централизованная платформа для конфигурирования, развёртывания и мониторинга honeypot-ловушек разного уровня взаимодействия (Low / Medium) со скрытым каналом управления.

## Цель

Распределённая система honeypot'ов с изолированным центром управления, маскировкой
канала связи и мониторингом атак в реальном времени.

## Ключевые особенности

- **Три разделённых контура**: центр управления, парк ловушек в DMZ и скрытый
  канал между ними
- **Маскировка канала**: телеметрия идёт по `/assets/v2/init` под виртуальным
  хостом `assets.cdn-static.example` и `Content-Type: application/javascript`
- **Маскировка агента**: нейтральное имя процесса и нейтральный артефакт `relay.pyz`
  без комментариев и докстрингов (MASK-4)
- **Реалтайм**: WebSocket + PostgreSQL `LISTEN/NOTIFY` с восстановлением пропусков
- **Буфер при обрыве**: локальная SQLite-очередь, дослылка и отчёт о потерях (FR-A4)
- **Живой IoC**: экспорт событий в CSV по тем же фильтрам, что и на экране (FR-C7)
- **Демо-стенд одной командой**: `make demo` поднимает центр и две ловушки

## Минимум для зачёта (Must)

- [x] `make demo` → центр + ловушки Low и Medium
- [x] CRUD профилей + регистрация ловушек с привязкой к профилю (FR-C1, FR-C2)
- [x] Защищённый канал: выдача конфигурации агенту и приём телеметрии (FR-C3)
- [x] События в PostgreSQL с фильтрами по ловушке, времени, источнику, типу (FR-C4)
- [x] Аутентификация оператора и разграничение доступа `admin`/`viewer` (FR-C5)
- [x] Два уровня взаимодействия: Low и Medium (FR-A1)
- [x] Логирование подключений, кредов, команд и запросов (FR-A2)
- [x] Периодическая телеметрия и обновление конфигурации на лету (FR-A3)
- [x] Буферизация и дослылка при потере связи (FR-A4)
- [x] TLS, скрытый endpoint, сетевая изоляция, скрытность агента (MASK-1…4)
- [x] Dashboard: список ловушек со статусами и лента событий в реальном времени
- [x] Живая демонстрация «атака → событие в центре» (`make demo-tour`)

Не реализовано и не выдаётся за готовое: оркестратор развёртывания (FR-C6), правила и
алерты (вторая половина FR-C7), honeytokens (FR-A6), mTLS (MASK-7), geo/ASN, агрегаты и
журнал аудита в интерфейсе. Подробно — `docs/architecture.md` §1.7.

## Документация

- [Архитектура](docs/architecture.md) и [схема](docs/architecture.mmd) — компоненты, потоки, сети, что маскируется
- [Схема БД](docs/database.md) и [ER](docs/database.mmd) — таблицы, индексы, инварианты, миграции
- [Контракт Security Event](docs/event_contract.md) — формат на проводе, идемпотентность, версии схемы
- [Развёртывание](docs/deployment.md) — CA, разнесённая топология, параметры агента, smoke-проверка
- [Сценарии демонстрации](docs/demo_attack.md) — что и какой командой показать
- [Acceptance report](docs/acceptance_report.md) — воспроизводимый MVP gate
- [Презентация](docs/presentation.md) и [screenshots](docs/screenshots/) — пакет защиты

## Профили ловушек

Профиль — версионируемый документ, полностью описывающий поведение ловушки
(FR-C1). Он задаётся в интерфейсе (Профили ловушек) и выдаётся агенту через
`GET /assets/v2/config`.

| Группа | Поля | Что делает |
|---|---|---|
| Уровень | `interaction_level` | `low` (баннеры и простые ответы) или `medium` (fake SSH/HTTP/БД) |
| Сервисы | `protocol`, `internal_port`, `banner`, `emulator_settings` | Какие порты слушать, что отдавать в баннере, `max_attempts`, `response_delay_ms`, `response_jitter_ms` |
| Приманки | `decoy_credentials` | Логин/пароль (и сервис), которые ловушка принимает вместо настоящей учётки |
| Логирование | `capture_credentials`, `capture_commands`, `capture_http_bodies`, `max_payload_bytes` | Что именно попадает в телеметрию и сколько текста разрешено |
| Маскировка | `beacon_interval_seconds`, `beacon_jitter_seconds`, `user_agent` | Каденция и размер батча beacon'а, джиттер интервала, `User-Agent` агента |

Две особенности:

- **Версионирование.** Правка профиля увеличивает `version`; отправка с устаревшим
  `If-Match` возвращает `409`, поэтому две вкладки не затирают друг друга.
- **Применение на лету.** Агент забирает конфигурацию каждые
  `PROFILE_CHECK_INTERVAL_SECONDS` и переключает сервисы без перезапуска.

Маскировка профиля — единственный способ настроить каденцию beacon'а: переменные
`BEACON_*` в окружении не читаются (см. `docs/deployment.md`).

## API

Интерактивная схема — на `/docs` (Swagger) и `/redoc` работающего центра; она
генерируется из кода, поэтому всегда актуальна. Кратко:

| Группа | Методы и пути |
|---|---|
| Аутентификация | `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me` |
| Профили | `POST/GET /api/v1/trap-profiles`, `GET/PUT/DELETE /api/v1/trap-profiles/{id}` |
| Ловушки | `POST/GET /api/v1/traps`, `GET/PATCH/DELETE /api/v1/traps/{id}`, `POST .../start`, `.../stop`, `.../revoke`, `.../restore`, `.../archive`, `.../enrollment-token` |
| События | `GET /api/v1/security-events` (фильтры + курсорная пагинация), `GET /api/v1/security-events/export.csv` (IoC, только CSV) |
| Realtime | `GET /ws` — рассылка событий по cookie оператора |
| Канал агента | `GET /assets/v2/config`, `POST /assets/v2/init`, `.../health`, `.../enroll`, `.../rotate` |
| Служебные | `GET /health`, `GET /ready` |

Аутентификация оператора — JWT в httpOnly-cookie; чтение доступно обеим ролям,
изменения — только `admin`. Контракт события целиком описан в
[docs/event_contract.md](docs/event_contract.md).

## Backend: локальный запуск

Требуется Python 3.11+ и PostgreSQL. Настройки читаются из переменных окружения;
основная — `DATABASE_URL` в формате
`postgresql+asyncpg://user:password@host:5432/database`.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/alembic upgrade head
.venv/bin/uvicorn center.api.main:app --reload
```

Схема API доступна на `http://localhost:8000/docs`, healthcheck — `GET /health`,
readiness — `GET /ready`, endpoint телеметрии — `POST /assets/v2/init`. Центр при
старте требует `JWT_SECRET` и `OPERATOR_PASSWORD` длиной не меньше 12 символов и
отказывается стартовать с заготовками из `.env.example`.

## Контейнерное развёртывание

Полный локальный demo запускается одной идемпотентной командой:

```bash
make demo
```

Она создаёт отсутствующую конфигурацию и CA, собирает образы, применяет
migrations, seed'ит Trap Profiles и Traps, а затем запускает Control Center и Agent'ов.
Существующие `.env`, сертификаты, PostgreSQL volume и Trap credentials не
перезаписываются. Подробный acceptance gate находится в
[`docs/acceptance_report.md`](docs/acceptance_report.md).

### Демонстрация возможностей

После `make demo` каждую возможность можно показать отдельной командой
(полный список — `make help`):

| Команда | Что показывает |
|---|---|
| `make demo-tour` | Обход всех сценариев ниже по порядку |
| `make demo-status` | Парк ловушек: статусы, профили, последнее событие |
| `make demo-attack` | Атаки на SSH, HTTP, MySQL и UDP ловушки |
| `make demo-payload` | Загрузка payload'а и его захват с sha256 |
| `make demo-export` | Выгрузка IoC в CSV (`EVENT_TYPE=`, `SOURCE_IP=`, `TRAP_ID=`, `EXPORT_LIMIT=`) |
| `make demo-lifecycle` | Стоп → старт → отзыв → восстановление ловушки и её само-восстановление |
| `make demo-rbac` | 401 без входа и 403 для read-only оператора |
| `make demo-masking` | Сборка артефакта агента и проверка, что он ничего не выдаёт |
| `make demo-trap-host` | Что видит атакующий с root на хосте ловушки |
| `make demo-smoke` | Доставка событий при обрыве связи (буфер + досылка) |
| `make demo-logs` | Логи центра и ловушек одновременно |

Read-only оператор для `make demo-rbac` заводится автоматически при `make demo`:
`OPERATOR_VIEWER_USERNAME` / `OPERATOR_VIEWER_PASSWORD` в `.env`. Без них центр
работает с единственным администратором.

### Тесты

`make test` запускает набор локально (PostgreSQL-тесты пропускаются).
`make test-db` поднимает одноразовый PostgreSQL и прогоняет всё без пропусков.

Локальная CA и серверный сертификат создаются командой `make certs`. Проверка
сертификата Agent'ами обязательна; режима отключения TLS verification нет.
Control Center и Traps запускаются одинаковыми образами как на одной машине,
так и на отдельных хостах. Настройка сертификатов, доверенного proxy и внешний
smoke test описаны в [руководстве по развёртыванию](docs/deployment.md).

Локальные Traps запускаются `make honeypots-up`; команда автоматически
подключает demo overlay. Base manifest без overlay предназначен для отдельного
DMZ-хоста и проверяется `make honeypots-distributed-config`.
