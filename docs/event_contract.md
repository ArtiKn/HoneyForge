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

Терминология соответствует `GLOSSARY.md`: `Security Event`, `Attack Session`,
`Trap`, `Agent`, `Control Center`.

Вне контракта: health/enrollment/rotation-эндпоинты Agent (см.
`docs/architecture.md`), а также всё, что Control Center выводит из события сам
(geo/ASN, агрегаты). Такие производные данные **не** меняют контракт провода.

## 2. Версионирование

Каждое событие несёт `schema_version`.

- Текущая (и единственная поддерживаемая) версия — **1**.
- Валидация требует `schema_version == 1` (поле типизировано как `Literal[1]`).
- Событие с другой версией отклоняется на входе.
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
| `schema_version` | int | да | Только `1` |
| `trap_id` | UUID | да | Должен совпадать с Trap, прошедшим аутентификацию в запросе |
| `attack_session_id` | UUID | да | Группировка связанных событий (см. §7) |
| `event_type` | enum | да | Одно из пяти значений (§6) |
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
поэтому посторонние ключи отклоняются.

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
разбирает его напрямую (`TelemetryBatch.model_validate_json`).

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
| `event_type` | Один из пяти типов |
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

## 11. Точки расширения

Приведённые ниже Bonus-возможности добавляются так, чтобы не ломать контракт
версии 1 и уже сохранённые записи.

### 11.1. Geo/ASN обогащение

- Обогащение выполняется **на стороне Control Center** (этап normalization/
  enrichment), а не Agent'ом.
- Результат — производные данные (страна, город, ASN, организация) — хранится
  отдельно от wire-контракта (отдельные поля/таблица обогащения) и **не**
  требует изменения `schema_version`.
- Отсутствие результата (приватный/неопределённый IP) — допустимое состояние,
  не ошибка.
- Обогащение идемпотентно относительно `id` события и может быть пересчитано
  без изменения исходного события.

### 11.2. Payload и файлы

- Крупные артефакты (загруженные файлы, тела запросов) не кладутся в `payload`
  «как есть»: `payload` остаётся компактным описанием.
- Сам артефакт хранится отдельно (blob-хранилище), а в событии/производной
  модели остаётся **ссылка + метаданные** (содержимое в base64 запрещено).
- Если метаданные артефакта должен присылать Agent, это **новое поле контракта**:
  сначала поднимается `schema_version`, затем Control Center начинает принимать
  и старую, и новую версию.

### 11.3. Агрегаты и read-модели

- Счётчики, топы, таймсерии и т.п. — производные read-модели.
- Они вычисляются из сохранённых `security_events`/`attack_sessions` и не
  меняют ни wire-контракт, ни запись события.
- Агрегаты обязаны быть воспроизводимы из исходных событий при той же
  retention-политике.

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
- Идемпотентность и правила сессий — `center/api/event_ingestion.py`.
- Схема таблиц и индексы — `docs/database.md`, `tests/test_postgres_schema.py`.
- Сквозной путь (buffer → доставка → exactly-once → realtime) —
  `docs/acceptance_report.md`.
