import { canManage, loadOperator } from './operator.js';

const api = '/api/v1/traps';
const profilesApi = '/api/v1/trap-profiles';
const form = document.querySelector('#trap-form');
const list = document.querySelector('#trap-list');
const notice = document.querySelector('#notice');
const tokenLabel = document.querySelector('#enrollment-token');
const profileSelect = form.elements.trap_profile_id;
let traps = [];
let profiles = [];
let canWrite = true;

function statusLabel(status) {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function formatTimestamp(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

async function request(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  if (response.status === 401) {
    window.location.replace('/login.html');
    throw new Error('Authentication required');
  }
  if (!response.ok && response.status !== 204) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || 'The Control Center could not complete that action.');
  }
  return response;
}

function profileName(profileId) {
  const profile = profiles.find(candidate => candidate.id === profileId);
  return profile ? profile.name : '—';
}

function actionButton(label, className, trap, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `button ${className}`;
  button.textContent = label;
  button.addEventListener('click', () => handler(trap));
  return button;
}

function renderTable() {
  if (!traps.length) {
    list.innerHTML = '<tr><td colspan="8" class="empty">No Traps registered yet. Register the first one above.</td></tr>';
    return;
  }
  list.replaceChildren(...traps.map(trap => {
    const row = document.createElement('tr');
    row.className = 'trap-row';
    row.dataset.trapId = trap.id;

    const name = document.createElement('td');
    name.textContent = trap.name;

    const profile = document.createElement('td');
    profile.textContent = profileName(trap.trap_profile_id);

    const status = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'trap-status';
    badge.dataset.status = trap.display_status || trap.status;
    badge.textContent = statusLabel(trap.display_status || trap.status);
    status.append(badge);

    const lastSeen = document.createElement('td');
    lastSeen.textContent = formatTimestamp(trap.last_seen_at);

    const ip = document.createElement('td');
    ip.textContent = trap.ip_address || '—';

    const hostname = document.createElement('td');
    hostname.textContent = trap.hostname || '—';

    const enabled = document.createElement('td');
    enabled.textContent = trap.enabled ? 'Enabled' : 'Disabled';

    const actions = document.createElement('td');
    actions.className = 'trap-actions';
    const terminal = trap.is_archived || trap.status === 'revoked';
    if (!canWrite) {
      actions.textContent = 'View only';
    } else if (!terminal) {
      actions.append(
        actionButton('Start', 'trap-start', trap, current => act(`${api}/${current.id}/start`)),
        actionButton('Stop', 'secondary trap-stop', trap, current => act(`${api}/${current.id}/stop`)),
        actionButton('Revoke', 'danger trap-revoke', trap, current => revoke(current)),
        actionButton('Archive', 'quiet trap-archive', trap, current => archive(current)),
      );
    } else if (!trap.is_archived) {
      actions.append(
        actionButton('Archive', 'quiet trap-archive', trap, current => archive(current)),
      );
    } else {
      actions.textContent = 'Archived';
    }

    row.append(name, profile, status, lastSeen, ip, hostname, enabled, actions);
    return row;
  }));
}

async function loadTraps() {
  traps = await (await request(api)).json();
  renderTable();
}

async function loadProfiles() {
  profiles = await (await request(profilesApi)).json();
  const selectable = profiles.filter(profile => !profile.is_archived);
  profileSelect.replaceChildren(...selectable.map(profile => {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = `${profile.name} · ${profile.interaction_level} · v${profile.version}`;
    return option;
  }));
  if (!selectable.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No active Trap Profiles';
    option.disabled = true;
    option.selected = true;
    profileSelect.append(option);
    form.querySelector('[type="submit"]').disabled = true;
  }
}

function reportError(error) {
  notice.textContent = error.message;
  notice.className = 'notice error';
}

async function act(url) {
  notice.textContent = 'Applying…';
  notice.className = 'notice';
  try {
    await request(url, { method: 'POST' });
    await loadTraps();
    notice.textContent = 'Trap updated.';
    notice.className = 'notice';
  } catch (error) {
    reportError(error);
  }
}

async function revoke(trap) {
  if (!window.confirm(`Revoke “${trap.name}”? Its credentials stop working immediately.`)) return;
  await act(`${api}/${trap.id}/revoke`);
}

async function archive(trap) {
  if (!window.confirm(`Archive “${trap.name}”? It stops presenting services but keeps its history.`)) return;
  await act(`${api}/${trap.id}/archive`);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!canWrite) return;
  notice.textContent = 'Registering…';
  notice.className = 'notice';
  tokenLabel.textContent = '';
  const body = {
    name: form.elements.name.value.trim(),
    trap_profile_id: profileSelect.value,
  };
  const hostname = form.elements.hostname.value.trim();
  if (hostname) body.hostname = hostname;
  const region = form.elements.region.value.trim();
  if (region) body.region = region;
  try {
    const created = await (await request(api, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })).json();
    tokenLabel.textContent = `Enrollment token: ${created.enrollment_token}`;
    form.reset();
    await loadTraps();
    notice.textContent = 'Trap registered. Enroll the Agent with the token above.';
    notice.className = 'notice';
  } catch (error) {
    reportError(error);
  }
});

document.querySelector('#refresh').addEventListener('click', () => {
  loadTraps().catch(reportError);
});
document.querySelector('#logout').addEventListener('click', async () => {
  await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
  window.location.replace('/login.html');
});

async function applyOperator(operator) {
  canWrite = canManage(operator);
  const label = document.querySelector('#operator');
  if (label && operator) {
    label.textContent = `Operator: ${operator.username} (${operator.role})`;
  }
  if (!canWrite) {
    [...form.elements].forEach(control => {
      control.disabled = true;
    });
    notice.textContent = 'Read-only Operator: your role cannot register or change Traps.';
    notice.className = 'notice';
  }
}

loadOperator()
  .then(operator => {
    applyOperator(operator);
    return Promise.all([loadProfiles(), loadTraps()]);
  })
  .catch(reportError);
