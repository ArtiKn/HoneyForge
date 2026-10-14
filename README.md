# HoneyForge

> Конструктор и центр управления реалистичными ловушками-приманками.  
> Кейс III Межрегионального хакатона **UmirHack**.

Централизованная платформа для конфигурирования, развёртывания и мониторинга honeypot-ловушек разного уровня взаимодействия (Low / Medium) со скрытым каналом управления.

## Цель

Реализовать распределённую систему honeypot'ов с изолированным центром управления, маскировкой канала связи и мониторингом атак в реальном времени.

## Ключевые особенности

- **Два контура**: Control Plane (защищённый сервер) и Data Plane (DMZ)
- **Маскировка трафика**: телеметрия идёт по URI `/assets/v2/init` под видом CDN-статики
- **Реалтайм**: WebSocket + PostgreSQL `LISTEN/NOTIFY`
- **Буфер при обрыве**: локальный SQLite-буфер + дослылка (FR-A4)
- **TLS + jitter**: скрытность канала связи (MASK-1, MASK-5)

## Документация

- [Архитектура](docs/architecture.md) — компоненты, потоки, сетевая изоляция
- [Схема БД](docs/database.md) — ER-диаграмма, таблицы, индексы, триггер NOTIFY
- [Развёртывание](docs/deployment.md) — demo CA, разнесённая топология и smoke-проверка
- [Сценарии демонстрации](docs/demo_attack.md) — атака → событие в центре
- [Acceptance report](docs/acceptance_report.md) — воспроизводимый MVP gate
- [Презентация](docs/presentation.md) и [screenshots](docs/screenshots/) — пакет защиты

## Минимум для зачёта (Must)

- [ ] `docker compose up` → центр + минимум 2 ловушки
- [ ] CRUD профилей + регистрация ловушек (FR-C1, C2)
- [ ] Приём телеметрии → сохранение в Postgres (FR-C3, C4)
- [ ] Low + Medium ловушки с логированием (FR-A1–A3)
- [ ] Буфер + дослылка при обрыве (FR-A4)
- [ ] TLS + скрытый endpoint + маскировка процесса (MASK-1,2,4)
- [ ] Dashboard: список ловушек + лента событий (WebSocket)
- [ ] Живая демонстрация «атака → событие в центре»

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

Документация API будет доступна по адресу `http://localhost:8000/docs`,
healthcheck — `GET /health`, readiness — `GET /ready`, endpoint телеметрии —
`POST /assets/v2/init`.

## Контейнерное развёртывание

Полный локальный demo запускается одной идемпотентной командой:

```bash
make demo
make demo-attack
make demo-smoke
```

Она создаёт отсутствующую конфигурацию и CA, собирает образы, применяет
migrations, seed'ит Trap Profiles и Traps, а затем запускает Control Center и Agent'ов.
Существующие `.env`, сертификаты, PostgreSQL volume и Trap credentials не
перезаписываются. Подробный acceptance gate находится в
[`docs/acceptance_report.md`](docs/acceptance_report.md).

Локальная CA и серверный сертификат создаются командой `make certs`. Проверка
сертификата Agent'ами обязательна; режима отключения TLS verification нет.
Control Center и Traps запускаются одинаковыми образами как на одной машине,
так и на отдельных хостах. Настройка сертификатов, доверенного proxy и внешний
smoke test описаны в [руководстве по развёртыванию](docs/deployment.md).

Локальные Traps запускаются `make honeypots-up`; команда автоматически
подключает demo overlay. Base manifest без overlay предназначен для отдельного
DMZ-хоста и проверяется `make honeypots-distributed-config`.
