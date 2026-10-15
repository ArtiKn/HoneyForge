// Refresh visible views without overlapping requests or resetting active edits.
export function startLiveRefresh(refresh, interval = 5000) {
  let pending = false;
  const update = async () => {
    if (document.hidden || pending) return;
    pending = true;
    try { await refresh(); } catch { /* Retry after a temporary network failure. */ }
    finally { pending = false; }
  };
  const timer = window.setInterval(update, interval);
  document.addEventListener('visibilitychange', update);
  window.addEventListener('focus', update);
  window.addEventListener('pagehide', () => {
    window.clearInterval(timer);
    document.removeEventListener('visibilitychange', update);
    window.removeEventListener('focus', update);
  }, { once: true });
}
