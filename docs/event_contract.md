# HoneyForge — контракт Security Event

Этот документ фиксирует контракт между Agent и Control Center: полную схему
Security Event на проводе, правила идентичности и идемпотентности, проекцию в
базу, транспорт и **правила расширения** (geo/ASN, payload/файлы, агрегаты),
чтобы новые возможности добавлялись без ломки существующих Agent и записей.

Источник истины по именам — код:

- схема провода — `center/api/schemas/security_event.py`;
- конверт батча — `center/api/schemas/telemetry.py`;
- приём — `center/api/routers/telemetry.py`, `center/api/event_ingestion.py`;
- хранение — `center/api/models/security_event.py`, `center/api/models/attack_session.py`;
- чтение — `center/api/routers/security_events.py`, `center/api/security_event_query.py`.

## 1. Область и границы

Контракт описывает **только** путь телеметрии Agent → Control Center:

- Agent формирует Security Event по наблюдению за взаимодействием с сервисом Trap.
- Agent складывает события в локальную очередь (SQLite на стороне Agent) и
  доставляет батчами по замаскированному TLS-каналу.
- Control Center валидирует, обогащает и сохраняет событие, а затем публикует
  факт его появления в realtime-канал.

Терминология соответствует [`../GLOSSARY.md`](../GLOSSARY.md): `Security Event`,
`Attack Session`, `Trap`, `Agent`, `Control Center`.

Вне контракта: служебные эндпоинты агента (см. §8.1), а также всё, что Control Center
выводит из события сам (geo/ASN, агрегаты — **пока не реализовано**). Такие
производные данные **не** меняют контракт провода.

## 2. Версионирование

Каждое событие несёт `schema_version`.

- Поддерживаемые версии — **1 и 2** (`Literal[1, 2]`).
- Версия 2 добавляет ограниченный сбор payload и fake-БД (§13).
- Событие с неизвестной версией отклоняется на входе.
- Любое **agent-supplied** изменение формы события требует новой версии
  `schema_version` (см. §9), потому что и конверт, и payload используют
  `extra="forbid"`.

## 3. Конверт доставки (batch)

```json
{ "events": [ { "id": "…", "schema_version": 1, "…": "…" } ] }
```

| Правило | Значение |
|---|---|
| Корневой объект | `{ "events": [...] }`, лишние поля запрещены (`extra="forbid"`) |
| Максимум событий в батче | 500 |
| Порядок в ответе | `accepted` повторяет `id` всех событий запроса в исходном порядке |
| Атомарность | один батч — одна транзакция: либо весь применён, либо отклонён |

## 4. Идентичность и идемпотентность

`id` — одновременно идентификатор события и **ключ идемпотентной доставки**.

- Повторная доставка уже сохранённого события допускается: Agent может
  переслать батч после сбоя сети.
- Повтор **принимается как дубликат без изменений**, если все поля совпадают
  (см. `SecurityEventIngestor._same_event`).
- Конфликт, когда тот же `id` приходит **с другими данными**, отклоняется
  ответом `422 Unprocessable Content`.
- Дубликаты внутри одного батча с разными данными также отклоняются `422`.
- Гарантия exactly-once обеспечивается уникальным `id` в PostgreSQL
  (`INSERT … ON CONFLICT DO NOTHING` + advisory-локи), а не порядком доставки.

`Attack Session` создаётся по `attack_session_id` из первого события, которое
на неё ссылается; повторные события лишь присоединяются к ней.

## 5. Общие поля Security Event

| Поле | Тип | Обязательное | Ограничения и смысл |
|---|---|---|---|
| `id` | UUID | да | Идентификатор и ключ идемпотентности события |
| `schema_version` | int | да | `1` или `2` |
| `trap_id` | UUID | да | Должен совпадать с Trap, прошедшим аутентификацию в запросе |
| `attack_session_id` | UUID | да | Группировка связанных событий (см. §7) |
| `event_type` | enum | да | Базовый тип (§6) или расширение v2 (§13) |
| `observed_at` | datetime | да | Момент наблюдения **с UTC-смещением**; нормализуется в UTC |
| `source_ip` | IPv4/IPv6 | да | Источник наблюдаемого взаимодействия |
| `source_port` | int \| null | да\* | `0..65535`; для поддерживаемых `event_type` обязан быть задан |
| `target_service` | str \| null | да\* | Имя сервиса Trap (например `ssh`, `http`, `mysql`) |
| `target_port` | int | да | `0..65535`; порт Trap, на который пришло взаимодействие |
| `payload` | object | да | Типизирован по `event_type` (§6); по умолчанию `{}` |

\* Для **всех** поддерживаемых `event_type` и `source_port`, и `target_service`
обязаны быть непустыми — иначе событие отклоняется.

Валидация `observed_at`: наивный timestamp (без смещения) отклоняется.
Control Center нормализует значение к UTC.

## 6. Типы событий и payload

Полезная нагрузка (`payload`) строгая: каждая модель имеет `extra="forbid"`,
посторонние ключи отклоняются. Всего типов семь: пять базовых (schema v1) и два
расширения (schema v2, §13).

| Тип | Кто порождает | Версия |
|---|---|---|
| `connection_opened` / `connection_closed` | Все ловушки, Low и Medium | 1 |
| `authentication_attempt` | SSH, MySQL, fake HTTP-админка | 1 (для MySQL — 2, §13) |
| `command_entered` | Fake-shell Medium | 1 (для SSH — 2, §13) |
| `http_request` | Low-HTTP и fake HTTP Medium | 1 |
| `payload_received` | TCP/UDP/HTTP-тела | 2 (§13) |
| `database_query` | Fake-БД Medium и Low-MySQL | 2 (§13) |

### `connection_opened` — открыто соединение с сервисом Trap

| Поле | Тип | Ограничения |
|---|---|---|
| `banner` | str | 1..1024 |

```json
{ "banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" }
```

### `authentication_attempt` — попытка аутентификации

| Поле | Тип | Ограничения |
|---|---|---|
| `username` | str | 1..256 |
| `password` | str | ≤ 1024 (может быть пустым) |
| `accepted` | bool | Ложь для отклонённой попытки |

```json
{ "username": "root", "password": "toor", "accepted": false }
```

### `command_entered` — введена команда в fake-shell

| Поле | Тип | Ограничения |
|---|---|---|
| `command` | str | ≤ 4096 |

```json
{ "command": "cat /etc/passwd" }
```

### `http_request` — HTTP-запрос

| Поле | Тип | Ограничения |
|---|---|---|
| `method` | str | 1..16 |
| `path` | str | 1..2048 |
| `http_version` | enum | `HTTP/1.0` или `HTTP/1.1` |
| `bytes_received` | int | ≥ 0 |

```json
{ "method": "GET", "path": "/.env", "http_version": "HTTP/1.1", "bytes_received": 87 }
```

### `connection_closed` — соединение закрыто

| Поле | Тип | Ограничения |
|---|---|---|
| `bytes_sent` | int | ≥ 0 |
| `session_expired` | bool | По умолчанию `false`; `true` — закрытие по inactivity |

```json
{ "bytes_sent": 512, "session_expired": false }
```

## 7. Правила Attack Session

`Attack Session` — ограниченная последовательность связанных Security Events
одного Trap (см. `GLOSSARY.md`).

- Для соединение-ориентированных протоколов — одна сессия на одно соединение.
- Для HTTP — активность одного `source_ip`, разделённая не более чем 15
  минутами неактивности (сессия объединяет несколько коротких TCP-соединений).
- Поля сессии при создании: `id = attack_session_id`, `trap_id`, `source_ip`,
  `started_at = observed_at` первого события, `protocol = target_service`
  (или `"unknown"`), `metadata = {}`.
- `ended_at` обновляется при `connection_closed`, **кроме** HTTP-сессий:
  HTTP-сессия закрывается по неактивности, а не по каждому сокету. Исключение —
  `connection_closed` c `session_expired = true`, который закрывает HTTP-сессию.
- Все события сессии обязаны принадлежать тому же `trap_id`, иначе — `422`.

## 8. Транспорт и маскировка

| Аспект | Значение |
|---|---|
| Метод и путь | `POST /assets/v2/init` (маскировка под CDN-инициализацию) |
| Content-Type | `application/javascript` или `application/json` |
| Аутентификация | `Authorization: Bearer <agent credential>` |
| Неверный credential | `401` |
| Событие с чужим `trap_id` | `422` (сравнивается с аутентифицированным Trap) |
| Успех | `200 {"accepted": ["<uuid>", …]}` |
| Ping | `GET /api/telemetry/ping` |

Тело передаётся как JSON даже под `application/javascript`; Control Center
разбирает его напрямую (`TelemetryBatch.model_validate_json`). Максимум — 500
событий в батче.

### 8.1. Служебные эндпоинты агента

Они не часть контракта события, но по тому же каналу и с тем же bearer-секретом:

| Эндпоинт | Назначение |
|---|---|
| `GET /assets/v2/config` | Конфигурация ловушки: профиль, сервисы, `decoy_credentials`, `logging`, `masking` |
| `POST /assets/v2/enroll` | Первичная регистрация по одноразовому токену; выдаёт секрет ловушки |
| `POST /assets/v2/health` | Heartbeat: версия профиля, глубина очереди, ошибки конфигурации, отчёт о потерянных событиях |
| `POST /assets/v2/rotate` | Ротация секрета с перекрывающимся окном, чтобы агент успел перечитать файл |

Ответ агента на `health` — `204 No Content`. Именно по этим отчётам центр переводит
ловушку в `online`/`degraded`/`offline`.

## 9. Проекция в базу данных

Событие сохраняется в `security_events` (см. `docs/database.md`):

`id`, `schema_version`, `trap_id`, `attack_session_id`, `event_type`,
`observed_at`, `source_ip`, `source_port`, `target_service`, `target_port`,
`payload` (JSONB), а также `received_at`.

- `received_at` проставляет **только Control Center** в момент приёма.
- Порядок выдачи и retention определяются `received_at`, а не `observed_at`.
- События, Attack Sessions и audit entries неизменяемы до retention cleanup.

## 10. Чтение (Control API)

`GET /api/v1/security-events` (доступ только у аутентифицированного Operator):

| Параметр | Смысл |
|---|---|
| `trap_id` | Фильтр по Trap |
| `attack_session_id` | Фильтр по сессии |
| `event_type` | Один из поддерживаемых типов (§6, §13) |
| `source_ip` | Фильтр по источнику (IPv4/IPv6) |
| `received_from`, `received_to` | Диапазон приёма; **обязателен UTC-смещение** |
| `cursor` | Курсор пагинации; некорректный курсор → `422` |
| `limit` | 1..500 (по умолчанию 100) |

- Порядок: `(received_at DESC, id DESC)`.
- Ответ — `SecurityEventPage`: `items` (`SecurityEventRead`), `next_cursor`.
- `SecurityEventRead` = событие + `received_at`.
- Если `received_from > received_to` → `422`.
- Realtime: PostgreSQL `NOTIFY` переносит **только UUID** события; listener
  перезагружает полную запись из БД и рассылает её в WebSocket `/ws`.

### 10.1. Экспорт IoC в CSV (FR-C7)

`GET /api/v1/security-events/export.csv` — те же фильтры, что и у списка
(`trap_id`, `attack_session_id`, `event_type`, `source_ip`, `received_from`,
`received_to`), плюс `limit` 1..50 000 (по умолчанию 10 000). Формат STIX не
реализуется.

- Ответ: `text/csv; charset=utf-8`, `Content-Disposition: attachment` с именем
  `honeyforge-ioc-<UTC-таймстамп>.csv`, строки CRLF (RFC 4180).
- Колонки: `event_id`, `received_at`, `observed_at`, `trap_name`, `trap_id`,
  `attack_session_id`, `event_type`, `source_ip`, `source_port`,
  `target_service`, `target_port`, затем плоские поля payload
  (`username`, `accepted`, `command`, `cwd`, `http_method`, `http_path`,
  `query`, `database`, `succeeded`, `bytes_received`, `sha256`) и полный
  `payload` JSON.
- Пароли остаются внутри колонки `payload`: отдельной колонки нет, чтобы файл
  не разносил учётные данные по ячейкам.
- Значения, начинающиеся с `=`, `+`, `-`, `@`, — экранируются префиксом `'`,
  иначе Excel выполнит attacker-controlled команду из логина или команды.
- Порядок строк совпадает со списком: `(received_at DESC, id DESC)`, поэтому
  при ограничении `limit` в файл попадают самые свежие наблюдения.
- События одной партии имеют одинаковый `received_at`, порядок внутри неё задаёт
  `id`.

## 11. Точки расширения

Приведённые ниже Bonus-возможности добавляются так, чтобы не ломать контракт
версии 1 и уже сохранённые записи. **Сейчас ни одна из них не реализована** —
это зафиксированный план расширения, а не описание работающего кода.

### 11.1. Geo/ASN обогащение — не реализовано

- Обогащение выполняется **на стороне Control Center** (этап normalization/
  enrichment), а не Agent'ом.
- Результат — производные данные (страна, город, ASN, организация) — хранится
  отдельно от wire-контракта (отдельные поля/таблица обогащения) и **не**
  требует изменения `schema_version`.
- Отсутствие результата (приватный/неопределённый IP) — допустимое состояние,
  не ошибка.
- Обогащение идемпотентно относительно `id` события и может быть пересчитано
  без изменения исходного события.

### 11.2. Payload и файлы — частично реализовано

Реализовано: ограниченный фрагмент входа с хэшем в `payload_received` версии 2
(§13) и правило `max_payload_bytes` из профиля ловушки. Не реализовано: отдельное
blob-хранилище артефактов.

- Крупные артефакты (загруженные файлы, тела запросов) не кладутся в `payload`
  «как есть»: `payload` остаётся компактным описанием.
- Артефакт должен храниться отдельно, а в событии — **ссылка + метаданные** (полные
  файлы в base64 не передаются). Ограниченные фрагменты до 64 KiB допускаются в
  `payload_received` версии 2 (§13); это не хранилище артефактов.
- Если метаданные артефакта должен присылать Agent, это **новое поле контракта**:
  сначала поднимается `schema_version`, затем Control Center начинает принимать
  и старую, и новую версию.

### 11.3. Агрегаты и read-модели — не реализовано

Счётчики, топы и таймсерии для интерфейса оператора — производные read-модели.

- Они вычисляются из сохранённых `security_events`/`attack_sessions` и не
  меняют ни wire-контракт, ни запись события.
- Агрегаты обязаны быть воспроизводимы из исходных событий при той же
  retention-политике.
- Сейчас единственный источник агрегатов для UI — клиентский подсчёт по списку
  ловушек; `GET /api/v1/dashboard` отдаёт заглушку.

### 11.4. Правила изменения контракта

1. **Аддитивность.** Предпочитать добавление необязательных полей изменению
   смысла существующих. Существующее поле никогда не меняет смысл «на месте».
2. **`extra="forbid"`.** Конверт, событие и payload запрещают лишние ключи,
   поэтому любое новое **agent-supplied** поле требует bump `schema_version`
   и одновременной поддержки прежней версии на входе.
3. **Совместимость приёма.** Control Center принимает все ещё поддерживаемые
   `schema_version`; неизвестная версия и неизвестный `event_type` отклоняются.
4. **Производные данные — вне контракта.** geo/ASN, агрегаты и т.п. не являются
   частью wire-контракта и не требуют изменений на стороне Agent.
5. **Миграции БД.** Расширение хранения (новые колонки обогащения, ссылки на
   артефакты) выполняется отдельной Alembic-миграцией; существующие записи
   остаются валидными без backfill, если поле необязательное.

## 12. Проверяемость

- Схема провода и payload'ов — `center/api/schemas/security_event.py`.
- Конверт батча и лимит 500 — `center/api/schemas/telemetry.py`.
- Идемпотентность и правила сессий — `center/api/event_ingestion.py`.
- Чтение и фильтры — `center/api/routers/security_events.py`,
  `center/api/security_event_query.py`, `center/api/security_event_csv.py`.
- Схема таблиц и индексы — `docs/database.md`, `tests/test_postgres_schema.py`.
- Сквозной путь (буфер → доставка → exactly-once → realtime) покрыт тестами
  `tests/test_trap_lifecycle.py`; воспроизводимый прогон стенда —
  `make demo-smoke` и `docs/acceptance_report.md`.


## Настройки записи текстовых полей

`capture_credentials=false` заменяет и логин, и пароль на `<redacted>` в
`authentication_attempt`. Поля остаются обязательными, `accepted` сохраняется.
Флаг `capture_http_bodies` не управляет записью учётных данных: даже при его
отключении событие входа формируется по тому же контракту. Тела HTTP-запросов передаются отдельным событием `payload_received` версии 2
при включённых `capture_http_bodies` и `capture_credentials`. В версии 1 тела
не передаются. Отключение записи учётных данных также скрывает сырой payload,
чтобы он не дублировал пароль в теле запроса или бинарном потоке.

`capture_commands=false` записывает `<redacted>` вместо команды. Эти флаги
меняют только телеметрию, а не проверку пароля или поведение эмулятора.

`max_payload_bytes` — бюджет UTF-8-байтов **для каждого записываемого поля**
логина, пароля и команды, без размера JSON-обёртки. Значение `0` отключает
запись исходного текста и оставляет `<redacted>`. Служебные маркеры не входят
в бюджет. Дополнительно действуют ограничения контракта: логин — 256,
пароль — 1024, команда — 4096 символов. Усечение не разрывает UTF-8-символы;
если непустой логин не помещается целиком даже одним символом, записывается
`unknown`, чтобы сохранить обязательное непустое поле.


## 13. Версия 2: payload и fake-БД

Control Center принимает версии **1 и 2** одновременно. Исходные типы
событий сохраняют payload версии 1, кроме SSH-команд и MySQL-аутентификации.
`command_entered` версии 2 содержит `command` и `cwd` (до 1024 символов),
рабочий каталог до выполнения команды. `capture_commands` и бюджет записи
распространяются на оба поля.

В `authentication_attempt` для MySQL версии 2 к обязательным `username`, `password`, `accepted`
добавлены `auth_scheme="mysql_native_password"`, `auth_response` и `auth_challenge`
(каждое до 128 символов).
`password` содержит маркер `<challenge-response>`, а не исходный пароль;
`auth_response` — hex-ответ клиента, `auth_challenge` — hex случайного challenge.
При отключённом сборе или нулевом лимите все эти значения и логин заменяются
на `<redacted>`.

Новые типы (недопустимы с `schema_version=1`):

- `payload_received`: `kind` (`tcp`, `udp`, `http_body`), `encoding="base64"`,
  `data` (base64 фрагмента), `bytes_received`, `bytes_captured`, `truncated`,
  `redacted`, `sha256` (64 hex-символа либо null). Размер фрагмента ограничен
  `max_payload_bytes` и 65536 байтами. SHA-256 вычисляется по всему **наблюдённому**
  входу до усечения фрагмента; для TCP это ограниченное окно наблюдения, не весь поток.
  При redaction `data` пуст, `bytes_captured=0`, `sha256=null`; размеры остаются.
  HTTP-фрагмент — тело, включая multipart, без разбора и исполнения файла.
- `database_query`: `query` (до 4096 символов), `database` (до 128 символов),
  `succeeded` (bool). `capture_commands` управляет записью SQL и выбранной БД;
  при отключении оба текстовых поля содержат `<redacted>`.

Для обоих типов обязательны источник и целевой сервис. UUID, подтверждение,
дедупликация, хранение JSONB, REST-фильтры и realtime работают как для версии 1.
Один UDP datagram образует Attack Session с открытием, payload и закрытием.
Открытие обозначает наблюдение datagram, а не установление UDP-соединения.

Сначала примените миграцию `20261016_0006` и обновите Control Center, затем
Agent. Откат миграции блокируется, если события версии 2 уже сохранены:
история не удаляется автоматически ради возврата старого ограничения.
