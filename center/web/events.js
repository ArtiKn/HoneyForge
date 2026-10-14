const labels = {
  connection_opened: 'Connection opened',
  connection_closed: 'Connection closed',
  authentication_attempt: 'Authentication attempt',
  command_entered: 'Command entered',
  http_request: 'HTTP request',
};

function renderEvent(event) {
  const item = document.createElement('li');
  item.className = 'security-event reveal';

  const time = document.createElement('time');
  time.dateTime = event.received_at;
  time.textContent = new Date(event.received_at).toLocaleString();

  const title = document.createElement('strong');
  title.textContent = labels[event.event_type] || event.event_type;

  const route = document.createElement('span');
  route.textContent = `${event.source_ip}:${event.source_port ?? '—'} → ${event.target_service}:${event.target_port}`;

  const detail = document.createElement('code');
  detail.textContent = event.payload.banner || JSON.stringify(event.payload);

  item.append(time, title, route, detail);
  return item;
}

const stream = document.getElementById('event-stream');
const emptyState = document.getElementById('empty-events');
const seenEventIds = new Set();
let reconnectDelay = 250;
let activeSocket = null;

function displayEvent(event) {
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
    throw new Error('Authentication required');
  }
  if (!response.ok) throw new Error('Security Events unavailable');
  return response.json();
}

async function recoverGap(socket, bufferedEvents) {
  let cursor = null;
  do {
    const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
    const page = await fetchPage(`/api/v1/security-events${query}`);
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

fetchPage('/api/v1/security-events')
  .then(page => {
    page.items.forEach(event => displayEvent(event));
    emptyState.hidden = seenEventIds.size > 0;
    connectRealtime();
  })
  .catch(() => {
    emptyState.textContent = 'Security Events unavailable.';
  });
