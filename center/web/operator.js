// Shared Operator identity for the Control Center UI.
//
// The API enforces the Operator role on every request; this helper only lets
// the views hide controls a read-only Operator cannot use.

let operatorPromise;

export function loadOperator() {
  // Share the request between the header and the page's permission controls.
  return operatorPromise ??= fetchOperator();
}

async function fetchOperator() {
  try {
    const response = await fetch('/api/v1/auth/me', { credentials: 'same-origin' });
    if (response.status === 401) {
      window.location.replace('/login.html');
      return null;
    }
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

export function canManage(operator) {
  // Fail open when the identity endpoint is unavailable so a version mismatch
  // never locks an Operator out of the UI; the API still rejects the request.
  return operator === null || operator.role === 'admin';
}
