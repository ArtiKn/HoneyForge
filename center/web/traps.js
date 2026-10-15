import { startLiveRefresh } from './live-refresh.js';
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
let enrollmentToken = '';
function showToken(token = '') {
  enrollmentToken = token;
  tokenLabel.textContent = token ? `Токен регистрации: ${token}` : '';
  document.querySelector('#enrollment-token-row').hidden = !token;
  document.querySelector('#copy-token').textContent = 'Копировать';
}
document.querySelector('#copy-token').addEventListener('click', async () => {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(enrollmentToken);
    } else {
      const field = document.createElement('textarea');
      field.value = enrollmentToken;
      field.style.position = 'fixed';
      field.style.opacity = '0';
      document.body.append(field);
      field.select();
      const copied = document.execCommand('copy');
      field.remove();
      if (!copied) throw new Error('copy failed');
    }
    document.querySelector('#copy-token').textContent = 'Скопировано';
  } catch {
    notice.textContent = 'Не удалось скопировать токен. Выделите и скопируйте его вручную.';
    notice.className = 'notice error';
  }
});

function statusLabel(status) {
  return { provisioning: 'Подготовка', online: 'В сети', degraded: 'Работает с ошибками', offline: 'Не в сети', stopped: 'Остановлена', revoked: 'Доступ отозван', archived: 'В архиве' }[status] || status;
}

function formatTimestamp(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString('ru-RU');
}

async function request(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
  if (response.status === 401) {
    window.location.replace('/login.html');
    throw new Error('Необходимо войти в систему');
  }
  if (!response.ok && response.status !== 204) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || 'Не удалось выполнить действие в центре управления.');
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
    list.innerHTML = '<tr><td colspan="8" class="empty">Ловушек пока нет. Зарегистрируйте первую с помощью формы выше.</td></tr>';
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
    enabled.textContent = trap.enabled ? 'Включена' : 'Отключена';

    const actions = document.createElement('td');
    actions.className = 'trap-actions';
    const terminal = trap.is_archived || trap.status === 'revoked';
    if (!canWrite) {
      actions.textContent = 'Только просмотр';
    } else if (!terminal) {
      actions.append(
        actionButton('Запустить', 'trap-start', trap, current => act(`${api}/${current.id}/start`)),
        actionButton('Остановить', 'secondary trap-stop', trap, current => act(`${api}/${current.id}/stop`)),
        actionButton('Отозвать доступ', 'danger trap-revoke', trap, current => revoke(current)),
      );
    } else {
      actions.append(
        actionButton('Восстановить', 'trap-restore', trap, restore),
      );

    }

    if (canWrite) actions.append(actionButton('Удалить', 'danger trap-delete', trap, deleteTrap));

    row.append(name, profile, status, lastSeen, ip, hostname, enabled, actions);
    return row;
  }));
}

async function loadTraps() {
  traps = await (await request(api)).json();
  renderTable();
}

async function loadProfiles() {
  const previous = profileSelect.value;
  profiles = await (await request(profilesApi)).json();
  const selectable = profiles.filter(profile => !profile.is_archived);
  profileSelect.replaceChildren(...selectable.map(profile => {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = `${profile.name} · ${({ low: "Низкий уровень", medium: "Средний уровень", high: "Высокий уровень" })[profile.interaction_level] || profile.interaction_level} · v${profile.version}`;
    return option;
  }));
  if (selectable.some(profile => profile.id === previous)) profileSelect.value = previous;
  form.querySelector('[type="submit"]').disabled = !canWrite || !selectable.length;
  if (!selectable.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'Нет активных профилей ловушек';
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
  notice.textContent = 'Применение…';
  notice.className = 'notice';
  try {
    await request(url, { method: 'POST' });
    await loadTraps();
    notice.textContent = 'Ловушка обновлена.';
    notice.className = 'notice';
  } catch (error) {
    reportError(error);
  }
}

async function deleteTrap(trap) {
  if (!window.confirm(`Удалить ловушку «${trap.name}» безвозвратно? Все её события безопасности, сессии атак, токены и записи аудита будут удалены.`)) return;
  try {
    await request(`${api}/${trap.id}`, { method: 'DELETE' });
    showToken();
    await loadTraps();
    notice.textContent = 'Ловушка и все связанные данные удалены.';
    notice.className = 'notice';
  } catch (error) { reportError(error); }
}

async function revoke(trap) {
  if (!window.confirm(`Отозвать доступ для ловушки «${trap.name}»? Её учётные данные немедленно перестанут действовать.`)) return;
  await act(`${api}/${trap.id}/revoke`);
}

async function restore(trap) {
  if (!window.confirm(`Восстановить ловушку «${trap.name}»? Её можно будет повторно подключить, после чего сервисы возобновят работу.`)) return;
  notice.textContent = 'Восстановление…';
  notice.className = 'notice';
  showToken();
  try {
    const restored = await (await request(`${api}/${trap.id}/restore`, { method: 'POST' })).json();
    showToken(restored.enrollment_token);
    await loadTraps();
    notice.textContent = 'Ловушка восстановлена. Повторно подключите агента с токеном выше или выполните `make demo`.';
    notice.className = 'notice';
  } catch (error) {
    reportError(error);
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!canWrite) return;
  notice.textContent = 'Регистрация…';
  notice.className = 'notice';
  showToken();
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
    showToken(created.enrollment_token);
    form.reset();
    await loadTraps();
    notice.textContent = 'Ловушка зарегистрирована. Подключите агента с токеном выше.';
    notice.className = 'notice';
  } catch (error) {
    reportError(error);
  }
});

document.querySelector('#logout').addEventListener('click', async () => {
  await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
  window.location.replace('/login.html');
});

async function applyOperator(operator) {
  canWrite = canManage(operator);
  if (!canWrite) {
    [...form.elements].forEach(control => {
      control.disabled = true;
    });
    notice.textContent = 'Доступ только для просмотра: ваша роль не позволяет регистрировать и изменять ловушки.';
    notice.className = 'notice';
  }
}

loadOperator()
  .then(operator => {
    applyOperator(operator);
    return Promise.all([loadProfiles(), loadTraps()]);
  })
  .then(() => startLiveRefresh(async () => {
    await loadProfiles();
    await loadTraps();
  }))
  .catch(reportError);
