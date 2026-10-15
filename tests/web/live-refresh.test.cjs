const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

test('refresh pauses in background, prevents overlap, resumes and cleans up', async () => {
  const listeners = {};
  let tick, cleared, count = 0, finish;
  const document = {
    hidden: false,
    addEventListener: (name, fn) => { listeners[name] = fn; },
    removeEventListener: name => { delete listeners[name]; },
  };
  const window = {
    setInterval: (fn, ms) => { tick = fn; assert.equal(ms, 5000); return 42; },
    clearInterval: id => { cleared = id; },
    addEventListener: document.addEventListener,
    removeEventListener: document.removeEventListener,
  };
  const context = vm.createContext({ document, window });
  vm.runInContext(readFileSync('center/web/live-refresh.js', 'utf8').replace('export function', 'function'), context);
  context.startLiveRefresh(() => { count++; return new Promise(resolve => { finish = resolve; }); });
  const first = tick();
  await tick();
  assert.equal(count, 1);
  finish(); await first;
  document.hidden = true;
  await tick(); assert.equal(count, 1);
  document.hidden = false;
  const resumed = listeners.visibilitychange();
  assert.equal(count, 2);
  finish(); await resumed;
  listeners.pagehide();
  assert.equal(cleared, 42);
  assert.equal(listeners.focus, undefined);
});
