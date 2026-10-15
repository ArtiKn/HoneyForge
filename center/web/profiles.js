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

function addService(value = {}) {
  const row = template.content.firstElementChild.cloneNode(true);
  row.querySelector('[name="protocol"]').value = value.protocol || 'ssh';
  row.querySelector('[name="internal_port"]').value = value.internal_port || 22;
  row.querySelector('[name="banner"]').value = value.banner || '';
  row.querySelector('[name="emulator_settings"]').value = JSON.stringify(value.emulator_settings || {}, null, 2);
  row.querySelector('.remove-service').addEventListener('click', () => {
    if (services.children.length > 1) row.remove();
  });
  services.append(row);
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
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  if (response.status === 401) {
    window.location.replace('/login.html');
    throw new Error('Authentication required');
  }
  if (response.status === 409) {
    throw new Error('This Trap Profile changed elsewhere. Reloaded the latest version.');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || 'The Control Center could not complete that action.');
  }
  return response;
}

function renderList() {
  if (!profiles.length) {
    list.innerHTML = '<p class="empty">No Trap Profiles yet. Create the first reusable service definition.</p>';
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
    meta[0].textContent = profile.interaction_level;
    meta[1].textContent = `v${profile.version}`;
    meta[2].textContent = profile.is_archived ? 'archived' : `${profile.services.length} service${profile.services.length === 1 ? '' : 's'}`;
    row.addEventListener('click', () => selectProfile(profile));
    return row;
  }));
}

function selectProfile(profile) {
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
  document.querySelector('#version-label').textContent = `Version ${profile.version}`;
  removeButton.hidden = false;
  removeButton.disabled = profile.is_archived;
  form.querySelector('[type="submit"]').disabled = profile.is_archived;
  document.querySelector('#add-service').disabled = profile.is_archived;
  document.querySelector('#add-credential').disabled = profile.is_archived;
  [...form.elements].forEach(control => {
    if (control !== removeButton) control.disabled = profile.is_archived;
  });
  notice.textContent = profile.is_archived ? 'Archived Trap Profiles remain readable for historical context.' : '';
  notice.className = 'notice';
  renderList();
}

function newProfile() {
  selected = null;
  form.reset();
  services.replaceChildren();
  credentials.replaceChildren();
  addService({ protocol: 'ssh', internal_port: 22 });
  form.elements.max_payload_bytes.value = 4096;
  document.querySelector('#editor-title').textContent = 'New Trap Profile';
  document.querySelector('#version-label').textContent = 'Not saved';
  removeButton.hidden = true;
  removeButton.disabled = false;
  form.querySelector('[type="submit"]').disabled = false;
  document.querySelector('#add-service').disabled = false;
  document.querySelector('#add-credential').disabled = false;
  [...form.elements].forEach(control => { control.disabled = false; });
  notice.textContent = '';
  notice.className = 'notice';
  renderList();
  form.elements.name.focus();
}

async function loadProfiles(preferredId = selected?.id) {
  const response = await request(api);
  profiles = await response.json();
  const preferred = profiles.find(profile => profile.id === preferredId);
  if (preferred) selectProfile(preferred);
  else if (profiles.length && selected) selectProfile(profiles[0]);
  else renderList();
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  notice.textContent = 'Saving…';
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
    notice.textContent = selected ? `Saved version ${saved.version}.` : 'Trap Profile created.';
    await loadProfiles(saved.id);
  } catch (error) {
    const message = error instanceof SyntaxError
      ? 'Emulator settings must be valid JSON.'
      : error.message;
    if (message.includes('changed elsewhere')) await loadProfiles();
    notice.textContent = message;
    notice.className = 'notice error';
  }
});

removeButton.addEventListener('click', async () => {
  if (!selected || !window.confirm(`Delete or archive “${selected.name}”?`)) return;
  try {
    await request(`${api}/${selected.id}`, {
      method: 'DELETE',
      headers: { 'If-Match': `"${selected.version}"` },
    });
    const oldId = selected.id;
    selected = null;
    await loadProfiles(oldId);
    const retained = profiles.find(profile => profile.id === oldId);
    if (retained) selectProfile(retained); else newProfile();
    notice.textContent = retained ? 'Trap Profile archived.' : 'Unused Trap Profile deleted.';
  } catch (error) {
    const message = error.message;
    if (message.includes('changed elsewhere')) await loadProfiles();
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
loadProfiles().catch(error => {
  notice.textContent = error.message;
  notice.className = 'notice error';
});
