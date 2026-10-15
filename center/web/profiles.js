import { startLiveRefresh } from './live-refresh.js';
import { canManage, loadOperator } from './operator.js';

const api = '/api/v1/trap-profiles';
const form = document.querySelector('#profile-form');
const list = document.querySelector('#profile-list');
const services = document.querySelector('#services');
const credentials = document.querySelector('#credentials');
const template = document.querySelector('#service-template');
const credentialTemplate = document.querySelector('#credential-template');
const notice = document.querySelector('#notice');
const removeButton = document.querySelector('#remove-profile');
let profiles = [];
let selected = null;
let canWrite = true;
let dirty = false;
form.addEventListener('input', () => { dirty = true; });
form.addEventListener('change', () => { dirty = true; });
form.addEventListener('click', event => {
  if (event.target.closest('#add-service, #add-credential, .remove-service, .remove-credential')) dirty = true;
});

function validateServiceProtocols() {
  const medium = form.elements.interaction_level.value === 'medium';
  services.querySelectorAll('[name="protocol"]').forEach(select => {
    select.querySelectorAll('option').forEach(option => {
      option.disabled = medium && option.value === 'udp';
    });
    select.setCustomValidity(medium && select.value === 'udp'
      ? 'Для уровня Medium выберите SSH, HTTP или MySQL. UDP доступен только для Low.'
      : '');
  });
}
form.elements.interaction_level.addEventListener('change', validateServiceProtocols);

function addService(value = {}) {
  const row = template.content.firstElementChild.cloneNode(true);
  row.querySelector('[name="protocol"]').value = value.protocol || 'ssh';
  row.querySelector('[name="internal_port"]').value = value.internal_port || 22;
  row.querySelector('[name="banner"]').value = value.banner || '';
  row.querySelector('[name="emulator_settings"]').value = JSON.stringify(value.emulator_settings || {}, null, 2);
  row.querySelector('.remove-service').addEventListener('click', () => {
    if (services.children.length > 1) row.remove();
  });
  row.querySelector('[name="protocol"]').addEventListener('change', validateServiceProtocols);
  services.append(row);
  validateServiceProtocols();
}

function addCredential(value = {}) {
  const row = credentialTemplate.content.firstElementChild.cloneNode(true);
  row.querySelector('[name="credential_service"]').value = value.service || '';
  row.querySelector('[name="credential_username"]').value = value.username || '';
  row.querySelector('[name="credential_password"]').value = value.password || '';
  row.querySelector('.remove-credential').addEventListener('click', () => row.remove());
  credentials.append(row);
}

function collectCredentials() {
  return [...credentials.querySelectorAll('.credential-row')].map(row => {
    const credential = {
      username: row.querySelector('[name="credential_username"]').value.trim(),
      password: row.querySelector('[name="credential_password"]').value,
    };
    const service = row.querySelector('[name="credential_service"]').value;
    if (service) credential.service = service;
    return credential;
  }).filter(credential => credential.username && credential.password);
}

function optionalNumber(name) {
  const value = form.elements[name].value.trim();
  return value === '' ? undefined : Number(value);
}

function payload() {
  const decoy = collectCredentials();
  const logging = {
    capture_credentials: form.elements.capture_credentials.checked,
    capture_commands: form.elements.capture_commands.checked,
    capture_http_bodies: form.elements.capture_http_bodies.checked,
    max_payload_bytes: Number(form.elements.max_payload_bytes.value || 0),
  };
  const masking = {};
  const beaconInterval = optionalNumber('beacon_interval_seconds');
  const beaconJitter = optionalNumber('beacon_jitter_seconds');
  const userAgent = form.elements.user_agent.value.trim();
  if (beaconInterval !== undefined) masking.beacon_interval_seconds = beaconInterval;
  if (beaconJitter !== undefined) masking.beacon_jitter_seconds = beaconJitter;
  if (userAgent) masking.user_agent = userAgent;
  return {
    name: form.elements.name.value.trim(),
    interaction_level: form.elements.interaction_level.value,
    services: [...services.querySelectorAll('.service-row')].map(row => {
      const service = {
        protocol: row.querySelector('[name="protocol"]').value,
        internal_port: Number(row.querySelector('[name="internal_port"]').value),
      };
      const banner = row.querySelector('[name="banner"]').value.trim();
      if (banner) service.banner = banner;
      const settings = row.querySelector('[name="emulator_settings"]').value.trim();
      service.emulator_settings = settings ? JSON.parse(settings) : {};
      return service;
    }),
    decoy_credentials: decoy,
    logging,
    masking,
  };
}

async function request(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
  if (response.status === 401) {
    window.location.replace('/login.html');
    throw new Error('Необходимо войти в систему');
  }
  if (response.status === 409 && options.method !== 'DELETE') {
    throw new Error('Профиль ловушки изменён в другом окне. Загружена последняя версия.');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (body.detail === 'Trap Profile changed; reload it before editing') {
      throw new Error('Профиль ловушки изменён в другом окне. Загружена последняя версия.');
    }
    const detail = Array.isArray(body.detail)
      ? body.detail.map(issue => issue.msg.replace(/^Value error, /, '')).join(' · ')
      : body.detail;
    throw new Error(detail || 'Не удалось выполнить действие в центре управления.');
  }
  return response;
}

function renderList() {
  if (!profiles.length) {
    list.innerHTML = '<p class="empty">Профилей ловушек пока нет. Создайте первый профиль с настройками сервисов.</p>';
    return;
  }
  list.replaceChildren(...profiles.map(profile => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'profile-row';
    row.dataset.profileId = profile.id;
    row.setAttribute('aria-current', String(selected?.id === profile.id));
    row.innerHTML = `<strong></strong><span class="profile-meta"><span></span><span></span><span></span></span>`;
    row.querySelector('strong').textContent = profile.name;
    const meta = row.querySelectorAll('.profile-meta span');
    meta[0].textContent = { low: 'Низкий уровень', medium: 'Средний уровень', high: 'Высокий уровень' }[profile.interaction_level] || profile.interaction_level;
    meta[1].textContent = `v${profile.version}`;
    meta[2].textContent = profile.is_archived ? 'В архиве' : `Сервисов: ${profile.services.length}`;
    row.addEventListener('click', () => selectProfile(profile));
    return row;
  }));
}

function selectProfile(profile) {
  dirty = false;
  selected = profile;
  form.elements.name.value = profile.name;
  form.elements.interaction_level.value = profile.interaction_level;
  services.replaceChildren();
  profile.services.forEach(addService);
  credentials.replaceChildren();
  (profile.decoy_credentials || []).forEach(addCredential);
  const logging = profile.logging || {};
  form.elements.capture_credentials.checked = logging.capture_credentials !== false;
  form.elements.capture_commands.checked = logging.capture_commands !== false;
  form.elements.capture_http_bodies.checked = logging.capture_http_bodies !== false;
  form.elements.max_payload_bytes.value = logging.max_payload_bytes ?? 4096;
  const masking = profile.masking || {};
  form.elements.beacon_interval_seconds.value = masking.beacon_interval_seconds ?? '';
  form.elements.beacon_jitter_seconds.value = masking.beacon_jitter_seconds ?? '';
  form.elements.user_agent.value = masking.user_agent || '';
  document.querySelector('#editor-title').textContent = profile.name;
  document.querySelector('#version-label').textContent = `Версия ${profile.version}`;
  const locked = profile.is_archived || !canWrite;
  removeButton.hidden = !canWrite;
  removeButton.disabled = !canWrite;
  form.querySelector('[type="submit"]').disabled = locked;
  document.querySelector('#add-service').disabled = locked;
  document.querySelector('#add-credential').disabled = locked;
  [...form.elements].forEach(control => {
    if (control !== removeButton) control.disabled = locked;
  });
  if (!canWrite) {
    notice.textContent = 'Доступ только для просмотра: ваша роль не позволяет изменять профили ловушек.';
  } else {
    notice.textContent = profile.is_archived ? 'Архивный профиль ловушки доступен для просмотра истории настроек.' : '';
  }
  notice.className = 'notice';
  renderList();
}

function newProfile() {
  dirty = false;
  selected = null;
  form.reset();
  services.replaceChildren();
  credentials.replaceChildren();
  addService({ protocol: 'ssh', internal_port: 22 });
  form.elements.max_payload_bytes.value = 4096;
  document.querySelector('#editor-title').textContent = 'Новый профиль ловушки';
  document.querySelector('#version-label').textContent = 'Не сохранён';
  removeButton.hidden = true;
  removeButton.disabled = false;
  form.querySelector('[type="submit"]').disabled = !canWrite;
  document.querySelector('#add-service').disabled = !canWrite;
  document.querySelector('#add-credential').disabled = !canWrite;
  [...form.elements].forEach(control => { control.disabled = !canWrite; });
  notice.textContent = canWrite ? '' : 'Доступ только для просмотра: ваша роль не позволяет изменять профили ловушек.';
  notice.className = 'notice';
  renderList();
  form.elements.name.focus();
}

async function loadProfiles(preferredId = selected?.id) {
  const response = await request(api);
  profiles = await response.json();
  const preferred = profiles.find(profile => profile.id === preferredId);
  if (preferred) selectProfile(preferred);
  else if (selected) newProfile();
  else renderList();
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!canWrite) return;
  notice.textContent = 'Сохранение…';
  notice.className = 'notice';
  try {
    const response = await request(selected ? `${api}/${selected.id}` : api, {
      method: selected ? 'PUT' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(selected ? { 'If-Match': `"${selected.version}"` } : {}),
      },
      body: JSON.stringify(payload()),
    });
    const saved = await response.json();
    notice.textContent = selected ? `Сохранена версия ${saved.version}.` : 'Профиль ловушки создан.';
    await loadProfiles(saved.id);
  } catch (error) {
    const message = error instanceof SyntaxError
      ? 'Настройки эмулятора должны содержать корректный JSON.'
      : error.message;
    if (message.includes('изменён в другом окне')) await loadProfiles();
    notice.textContent = message;
    notice.className = 'notice error';
  }
});

removeButton.addEventListener('click', async () => {
  if (!canWrite) return;
  if (!selected || !window.confirm(`Удалить профиль ловушки «${selected.name}»? Удаление необратимо. Назначенный ловушкам профиль сначала нужно заменить.`)) return;
  try {
    await request(`${api}/${selected.id}`, {
      method: 'DELETE',
      headers: { 'If-Match': `"${selected.version}"` },
    });
    const oldId = selected.id;
    selected = null;
    await loadProfiles(oldId);
    newProfile();
    notice.textContent = 'Профиль ловушки удалён.';
  } catch (error) {
    const message = error.message;
    if (message.includes('изменён в другом окне')) await loadProfiles();
    notice.textContent = message;
    notice.className = 'notice error';
  }
});

document.querySelector('#new-profile').addEventListener('click', newProfile);
document.querySelector('#add-service').addEventListener('click', () => addService());
document.querySelector('#add-credential').addEventListener('click', () => addCredential());
document.querySelector('#logout').addEventListener('click', async () => {
  await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
  window.location.replace('/login.html');
});

newProfile();
loadOperator()
  .then(operator => {
    canWrite = canManage(operator);
    document.querySelector('#new-profile').disabled = !canWrite;
    if (selected) selectProfile(selected); else newProfile();
  })
  .catch(() => {})
  .finally(() => {
    loadProfiles().catch(error => {
      notice.textContent = error.message;
      notice.className = 'notice error';
    });
  });

startLiveRefresh(async () => {
  const updated = await (await request(api)).json();
  const current = updated.find(profile => profile.id === selected?.id);
  profiles = updated;
  if (selected && !current) {
    newProfile();
    notice.textContent = 'Выбранный профиль ловушки удалён.';
  } else if (current && JSON.stringify(current) !== JSON.stringify(selected)) {
    if (!dirty) selectProfile(current);
    else {
      notice.textContent = 'Профиль изменён в другом окне. Откройте его заново, чтобы загрузить изменения; несохранённые правки сохранены в форме.';
      renderList();
    }
  } else renderList();
});
