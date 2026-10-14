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

fetch('/api/v1/security-events', { credentials: 'same-origin' })
  .then(response => {
    if (response.status === 401) window.location.replace('/login.html');
    if (!response.ok) throw new Error('Security Events unavailable');
    return response.json();
  })
  .then(page => {
    const events = page.items;
    const stream = document.getElementById('event-stream');
    events.forEach(event => stream.append(renderEvent(event)));
    document.getElementById('empty-events').hidden = events.length > 0;
  })
  .catch(() => {
    document.getElementById('empty-events').textContent = 'Security Events unavailable.';
  });
