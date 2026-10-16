# HoneyForge — Архитектура

## 1.1. Общая идея

HoneyForge — распределённая платформа-ловушка, разделённая на **два изолированных контура**:

- **Центр управления (Control Plane)** — разворачивается на защищённом сервере, недоступен из DMZ напрямую.
- **Парк ловушек (Data Plane)** — разворачивается в DMZ, каждая ловушка — отдельный контейнер, общается с центром только по одному замаскированному TLS-каналу.

Ключевой принцип: **атакующий не должен понять, что попал в ловушку**, а трафик агента не должен выглядеть как «телеметрия honeypot'а».

## 1.2. Компоненты

| Компонент | Роль | Где живёт |
|---|---|---|
| **Nginx (center)** | TLS-терминация, reverse-proxy, маскировка endpoint'ов | Control Plane |
| **FastAPI (center/api)** | REST API, JWT-аутентификация, WebSocket | Control Plane |
| **Collector** | Приём батчей телеметрии, нормализация, geoip, запись в БД | Control Plane |
| **pg_listener** | `LISTEN/NOTIFY` → рассылка событий в WebSocket | Control Plane |
| **PostgreSQL** | Хранилище (6+ таблиц), триггеры NOTIFY | Control Plane |
| **Web UI** | Статика (vanilla JS), dashboard, конструктор профилей | Control Plane |
| **Orchestrator** (Bonus) | Генерация compose-файла из профиля + деплой на хост | Control Plane |
| **Agent Low** | Слушатели портов + баннеры | DMZ |
| **Agent Medium** | Fake SSH / HTTP / shell | DMZ |
| **Honeytokens** (Bonus) | Генерация, размещение, детект | DMZ |

## 1.3. Потоки данных

**1) Атакующий → ловушка.**
Сканер/эксплойт попадает в Low/Medium honeypot, который отвечает реалистично (баннеры, тайминги, фейковый shell). Каждое взаимодействие превращается в **событие** (`event_schema.py`) с полями: `ts, honeypot_id, src_ip, src_port, dst_port, proto, action, creds, cmd, raw`.

**2) Ловушка → центр (телеметрия).**
Агент раз в N секунд (с джиттером ±30%) собирает батч событий из локального SQLite-буфера и отправляет `POST /assets/v2/init` — endpoint маскирован под CDN-статику. Канал — TLS (Bonus: mTLS).

**3) Центр → БД → UI.**
Collector нормализует батч, дополняет geoip, пишет в `events`/`sessions`. Postgres-триггер делает `NOTIFY events_new`. `pg_listener` ловит и пушит в WebSocket. Dashboard оператора обновляется в реальном времени.

**4) Оператор → центр.**
Логин (`/auth/login` → JWT) → CRUD профилей (`/profiles`) → регистрация ловушек (`/honeypots`) → фильтрация событий (`/events?filters=...`) → экспорт IoC (`GET /api/v1/security-events/export.csv` с теми же фильтрами, только CSV).

## 1.4. Сетевая изоляция

| Сеть | Кто в ней | Доступ |
|---|---|---|
| `mgmt_net` (internal) | API ↔ Postgres ↔ Collector ↔ pg_listener | Наружу — нет |
| `agent_egress_net` | Исходящий management-трафик Agent | Только TLS к внешнему адресу Control Center |
| `edge_net` | Nginx Control Center ↔ Интернет | 8443/tcp в demo, 443/tcp в distributed override |
| `honeypot_exposed` | Порты Low/Medium ловушек | Наружу открыты только эмулируемые порты (22, 80, 3306, …) |

Агент **не знает** внутренних адресов БД, у него на руках только `AGENT_TOKEN` и URL маскированного endpoint'а.

## 1.5. Что маскируется

| Что | Как |
|---|---|
| Endpoint телеметрии | URI `/assets/v2/init`, `Content-Type: application/javascript` |
| Тайминги beacon'а | `masking.beacon_interval_seconds` ± `beacon_jitter_seconds` (по умолчанию 30% интервала); без настроек Agent берёт `DELIVERY_INTERVAL_SECONDS` |
| Размер запросов beacon'а | Случайный батч 40–100% от лимита, чтобы соседние запросы отличались по весу |
| User-Agent агента | `masking.user_agent` из профиля (иначе — дефолтный клиент urllib) |
| Процесс Agent | Маскируется: `prctl(PR_SET_NAME)` + перезапись argv дают нейтральное имя (`syslog-relay`, настраивается через `PROCESS_MASK_NAME`) |
| Баннеры сервисов | Реалистичные строки (OpenSSH_8.9, nginx/1.24.0, MySQL 8.0) |
| Ответы fake-shell | Задержки как у настоящего bash: `response_delay_ms` + случайный разброс `response_jitter_ms` |
