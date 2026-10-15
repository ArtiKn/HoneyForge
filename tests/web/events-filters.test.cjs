const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

function page(search = '') {
  const fields = new Map();
  const field = name => {
    if (!fields.has(name)) fields.set(name, {
      value: '', validity: '', listeners: {},
      setCustomValidity(message) { this.validity = message; },
      reportValidity() {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
    });
    return fields.get(name);
  };
  let submit;
  let destination;
  const form = {
    elements: { namedItem: field },
    addEventListener(type, fn) { if (type === 'submit') submit = fn; },
  };
  const context = vm.createContext({
    URL, URLSearchParams, Date, Set,
    location: { search, assign(url) { destination = url; } },
    document: { getElementById(id) { return id === 'event-filters' ? form : {}; } },
    fetch: () => new Promise(() => {}),
  });
  vm.runInContext(readFileSync('center/web/events.js', 'utf8'), context);
  return { field, submit: () => submit({ preventDefault() {} }), destination: () => destination, matches: event => context.matchesFilters(event) };
}

test('restores local date and time and submits the same instant', () => {
  const instant = '2026-10-14T12:34:56.000Z';
  const ui = page(`?received_from=${encodeURIComponent(instant)}`);
  const local = new Date(instant);
  assert.equal(ui.field('received_from_time').value,
    [local.getHours(), local.getMinutes(), local.getSeconds()].map(n => String(n).padStart(2, '0')).join(':'));
  ui.submit();
  assert.equal(new URL(ui.destination(), 'http://localhost').searchParams.get('received_from'), instant);
});

test('date-only range includes the entire final day', () => {
  const ui = page();
  ui.field('received_from_date').value = '2026-10-14';
  ui.field('received_to_date').value = '2026-10-14';
  ui.submit();
  const query = new URL(ui.destination(), 'http://localhost').searchParams;
  assert.equal(query.get('received_from'), new Date('2026-10-14T00:00:00').toISOString());
  assert.equal(query.get('received_to'), new Date('2026-10-14T23:59:59').toISOString());
});

test('rejects reversed ranges and time without a date', () => {
  const ui = page();
  ui.field('received_to_time').value = '12:00';
  ui.field('received_to_time').listeners.input();
  assert.ok(ui.field('received_to_date').validity);
  ui.field('received_from_date').value = '2026-10-15';
  ui.field('received_to_date').value = '2026-10-14';
  ui.submit();
  assert.equal(ui.destination(), undefined);
  assert.ok(ui.field('received_to_date').validity);
  ui.field('received_to_date').value = '2026-10-16';
  ui.field('received_to_date').listeners.input();
  assert.equal(ui.field('received_to_date').validity, '');
});

test('normalizes IPv6 and whitespace and rejects an IP with a port', () => {
  const ui = page();
  ui.field('source_ip').value = '  2001:0DB8:0:0:0:0:0:1  ';
  ui.submit();
  assert.equal(new URL(ui.destination(), 'http://localhost').searchParams.get('source_ip'), '2001:db8::1');
  const invalid = page();
  invalid.field('source_ip').value = '192.0.2.44:1234';
  invalid.submit();
  assert.equal(invalid.destination(), undefined);
  assert.ok(invalid.field('source_ip').validity);
});

test('realtime IP matching uses the same normalized address as API queries', () => {
  const ui = page('?source_ip=2001%3A0DB8%3A0%3A0%3A0%3A0%3A0%3A1');
  assert.equal(ui.matches({ source_ip: '2001:db8::1', received_at: '2026-10-14T12:00:00Z' }), true);
  assert.equal(ui.matches({ source_ip: '2001:db8::2', received_at: '2026-10-14T12:00:00Z' }), false);
});
