# HoneyForge — схема базы данных

Эта схема соответствует MVP-спецификации и ADR-0004. В MVP ровно шесть таблиц; Honeytoken storage появится только вместе с Bonus-функцией.

```mermaid
erDiagram
    TRAP_PROFILES ||--o{ TRAPS : assigns
    TRAPS ||--o{ ATTACK_SESSIONS : observes
    TRAPS ||--o{ SECURITY_EVENTS : produces
    ATTACK_SESSIONS ||--o{ SECURITY_EVENTS : groups
    OPERATORS ||--o{ AUDIT_ENTRIES : records

    TRAP_PROFILES {
        uuid id PK
        text name UK
        text interaction_level
        jsonb services
        jsonb banners
        jsonb config
        int version
        bool is_archived
        timestamptz created_at
        timestamptz updated_at
    }
    TRAPS {
        uuid id PK
        text name
        uuid trap_profile_id FK
        bool is_archived
        bool enabled
        inet ip_address
        text hostname
        text status
        text agent_version
        timestamptz last_seen_at
        jsonb agent_meta
        timestamptz created_at
    }
    ATTACK_SESSIONS {
        uuid id PK
        uuid trap_id FK
        inet source_ip
        timestamptz started_at
        timestamptz ended_at
        text protocol
        jsonb metadata
    }
    SECURITY_EVENTS {
        uuid id PK
        int schema_version
        uuid trap_id FK
        uuid attack_session_id FK
        text event_type
        timestamptz observed_at
        timestamptz received_at
        inet source_ip
        int source_port
        text target_service
        int target_port
        jsonb payload
    }
    OPERATORS {
        uuid id PK
        text username UK
        text password_hash
        text role
        bool is_active
        timestamptz last_login_at
        timestamptz created_at
    }
    AUDIT_ENTRIES {
        bigserial id PK
        uuid operator_id FK
        text action
        text entity
        uuid entity_id
        jsonb details
        inet source_ip
        timestamptz created_at
    }
```

## Инварианты

- `SecurityEvent.id` — UUID события и идемпотентный ключ доставки.
- `received_at` задаётся Control Center; выдача Security Events сортируется по
  `(received_at DESC, id DESC)`, а `observed_at` показывается отдельно и не влияет
  на порядок или retention.
- Traps и ранее назначенные Trap Profiles архивируются, а Security Events, Attack Sessions и audit entries неизменяемы до retention cleanup.
- `Trap.enabled` — желаемое состояние оператора; `Trap.status` — фактическое
  состояние, которое подтверждает Agent через Health Report. `enabled = false`
  показывает Trap как `stopped`: Agent останавливает сервисы, но продолжает
  доставку буфера и Health Reports.
- Security data хранится `SECURITY_DATA_RETENTION_DAYS` (30 дней по умолчанию),
  audit entries — `AUDIT_ENTRY_RETENTION_DAYS` (365 дней); фоновая очистка
  запускается каждые `RETENTION_SWEEP_INTERVAL_SECONDS` (сутки по умолчанию).
- PostgreSQL notification передаёт только UUID Security Event; listener загружает полную запись из БД.

## Индексы Security Events

- `(received_at, id)` — стабильная cursor pagination.
- `(trap_id, received_at)`, `(attack_session_id, received_at)`,
  `(source_ip, received_at)` и `(event_type)` — фильтры расследования.

## Таблицы

| Таблица | Назначение |
|---|---|
| `trap_profiles` | Версионируемые настройки сервисов и поведения Trap |
| `traps` | Реестр развёрнутых Trap и их Trap Status |
| `attack_sessions` | Группировка связанных Security Events |
| `security_events` | Нормализованные наблюдения активности атакующего |
| `operators` | Аутентифицированные Operator |
| `audit_entries` | Изменяемые Operator действия, требующие аудита |
