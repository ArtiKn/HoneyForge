const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

test('operator menu closes outside, on focus loss, Escape and window blur', () => {
  const handlers = {}, documentHandlers = {}, windowHandlers = {};
  const inside = {};
  let focused = false;
  const menu = {
    open: true,
    contains: target => target === inside,
    addEventListener: (name, fn) => { handlers[name] = fn; },
    querySelector: () => ({ focus: () => { focused = true; } }),
  };
  vm.runInNewContext(readFileSync('center/web/header.js', 'utf8').replace(/^import .*;\n/, ''), {
    document: {
      querySelectorAll: () => [menu],
      getElementById: () => null,
      addEventListener: (name, fn) => { documentHandlers[name] = fn; },
    },
    window: { addEventListener: (name, fn) => { windowHandlers[name] = fn; } },
  });
  handlers.focusout({ relatedTarget: inside });
  assert.equal(menu.open, true);
  handlers.focusout({ relatedTarget: null });
  assert.equal(menu.open, false);
  menu.open = true;
  documentHandlers.pointerdown({ target: inside });
  assert.equal(menu.open, true);
  documentHandlers.pointerdown({ target: {} });
  assert.equal(menu.open, false);
  menu.open = true;
  handlers.keydown({ key: 'Escape' });
  assert.equal(menu.open, false);
  assert.equal(focused, true);
  menu.open = true;
  windowHandlers.blur();
  assert.equal(menu.open, false);
});
