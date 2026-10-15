const labels = {
  connection_opened: 'Соединение открыто',
  connection_closed: 'Соединение закрыто',
  authentication_attempt: 'Попытка аутентификации',
  command_entered: 'Введена команда',
  http_request: 'HTTP-запрос',
};

function renderEvent(event) {
  const item = document.createElement('li');
  item.className = 'security-event reveal';

  const times = document.createElement('div');
  times.className = 'event-times';
  for (const [label, value] of [
    ['Получено', event.received_at],
    ['Зафиксировано', event.observed_at],
  ]) {
    const row = document.createElement('span');
    const caption = document.createElement('span');
    caption.className = 'event-time-label';
    caption.textContent = label;
    const time = document.createElement('time');
    time.dateTime = value;
    time.textContent = new Date(value).toLocaleString('ru-RU');
    row.append(caption, time);
    times.append(row);
  }

  const title = document.createElement('strong');
  title.textContent = labels[event.event_type] || event.event_type;

  const route = document.createElement('span');
  route.textContent = `${event.source_ip}:${event.source_port ?? '—'} → ${event.target_service}:${event.target_port}`;

  const detail = document.createElement('code');
  detail.textContent = event.payload.banner || JSON.stringify(event.payload);

  item.append(times, title, route, detail);
  return item;
}

const stream = document.getElementById('event-stream');
const emptyState = document.getElementById('empty-events');
const filtersForm = document.getElementById('event-filters');
const seenEventIds = new Set();
const filterNames = [
  'trap_id',
  'attack_session_id',
  'event_type',
  'source_ip',
  'received_from',
  'received_to',
];
const pageParams = new URLSearchParams(location.search);
const filterParams = new URLSearchParams();
for (const name of filterNames) {
  const value = pageParams.get(name);
  if (!value) continue;
  filterParams.set(name, value);
  if (name.startsWith('received_')) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) continue;
    const pad = number => String(number).padStart(2, '0');
    filtersForm.elements.namedItem(`${name}_date`).value =
      `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    filtersForm.elements.namedItem(`${name}_time`).value =
      `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  } else {
    filtersForm.elements.namedItem(name).value = value;
  }
}

let reconnectDelay = 250;
let activeSocket = null;

for (const name of ['received_from', 'received_to']) {
  const date = filtersForm.elements.namedItem(`${name}_date`);
  const time = filtersForm.elements.namedItem(`${name}_time`);
  const validate = () => {
    date.setCustomValidity(time.value && !date.value ? 'Укажите дату для выбранного времени.' : '');
  };
  date.addEventListener('input', validate);
  time.addEventListener('input', validate);
}

filtersForm.addEventListener('submit', event => {
  event.preventDefault();
  const target = new URLSearchParams();
  for (const name of filterNames) {
    let value;
    if (name.startsWith('received_')) {
      const date = filtersForm.elements.namedItem(`${name}_date`).value;
      const time = filtersForm.elements.namedItem(`${name}_time`).value;
      if (!date) continue;
      value = new Date(`${date}T${time || (name === 'received_to' ? '23:59:59' : '00:00:00')}`).toISOString();
    } else {
      value = filtersForm.elements.namedItem(name).value;
    }
    if (value) target.set(name, value);
  }
  const from = target.get('received_from');
  const to = target.get('received_to');
  if (from && to && Date.parse(from) > Date.parse(to)) {
    const date = filtersForm.elements.namedItem('received_to_date');
    date.setCustomValidity('Конец периода должен быть не раньше начала.');
    date.reportValidity();
    return;
  }
  const query = target.toString();
  location.assign(query ? `/events.html?${query}` : '/events.html');
});

function securityEventsUrl(cursor = null) {
  const query = new URLSearchParams(filterParams);
  if (cursor) query.set('cursor', cursor);
  const encoded = query.toString();
  return `/api/v1/security-events${encoded ? `?${encoded}` : ''}`;
}

function matchesFilters(event) {
  const comparisons = {
    trap_id: event.trap_id,
    attack_session_id: event.attack_session_id,
    event_type: event.event_type,
    source_ip: event.source_ip,
  };
  for (const [name, actual] of Object.entries(comparisons)) {
    const expected = filterParams.get(name);
    if (expected && actual !== expected) return false;
  }
  const received = Date.parse(event.received_at);
  const from = filterParams.get('received_from');
  const to = filterParams.get('received_to');
  return (!from || received >= Date.parse(from))
    && (!to || received <= Date.parse(to));
}

function displayEvent(event) {
  if (!matchesFilters(event)) return false;
  if (seenEventIds.has(event.id)) return false;
  seenEventIds.add(event.id);
  const item = renderEvent(event);
  item.dataset.receivedAt = event.received_at;
  item.dataset.eventId = event.id;
  const receivedAt = Date.parse(event.received_at);
  const nextItem = Array.from(stream.children).find(existing => {
    const existingReceivedAt = Date.parse(existing.dataset.receivedAt);
    return existingReceivedAt < receivedAt
      || (existingReceivedAt === receivedAt && existing.dataset.eventId < event.id);
  });
  stream.insertBefore(item, nextItem || null);
  emptyState.hidden = true;
  return true;
}

async function fetchPage(url) {
  const response = await fetch(url, { credentials: 'same-origin' });
  if (response.status === 401) {
    window.location.replace('/login.html');
    throw new Error('Требуется вход оператора');
  }
  if (!response.ok) throw new Error('Не удалось загрузить события безопасности');
  return response.json();
}

async function recoverGap(socket, bufferedEvents) {
  let cursor = null;
  do {
    const page = await fetchPage(securityEventsUrl(cursor));
    page.items.forEach(event => displayEvent(event));
    cursor = page.next_cursor;
  } while (cursor && activeSocket === socket);
  if (activeSocket !== socket) return;
  const queued = bufferedEvents.splice(0);
  queued.forEach(event => displayEvent(event));
  return true;
}

function connectRealtime() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  const bufferedEvents = [];
  let recovering = true;
  activeSocket = socket;

  socket.onopen = async () => {
    reconnectDelay = 250;
    try {
      recovering = true;
      if (await recoverGap(socket, bufferedEvents)) recovering = false;
    } catch (_error) {
      socket.close();
    }
  };
  socket.onmessage = message => {
    const event = JSON.parse(message.data);
    if (recovering) bufferedEvents.push(event);
    else displayEvent(event);
  };
  socket.onclose = () => {
    if (activeSocket !== socket) return;
    activeSocket = null;
    window.setTimeout(connectRealtime, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 10000);
  };
  socket.onerror = () => socket.close();
}

fetchPage(securityEventsUrl())
  .then(page => {
    page.items.forEach(event => displayEvent(event));
    emptyState.hidden = seenEventIds.size > 0;
    connectRealtime();
  })
  .catch(() => {
    emptyState.textContent = 'Не удалось загрузить события безопасности.';
  });
