// Standalone entry enhancement only; no student renderer or tab behavior changes.
let generation = 0;
let active = null;
function invalidate() {
  generation += 1;
  if (active) { active.controller.abort(); clearTimeout(active.timer); }
  active = null;
}
addEventListener('pagehide', invalidate);
addEventListener('pageshow', event => { if (event.persisted) refreshName(); });
const sidebar = document.querySelector('.sidebar');
if (sidebar && !sidebar.querySelector('a[data-personal-ai-link]')) {
  const link = document.createElement('a');
  link.href = '/personal/';
  link.dataset.personalAiLink = 'true';
  link.className = 'btn btn-link';
  link.textContent = '개인 AI · 보안 이벤트 설명';
  sidebar.append(link);
}
// Close slide-out hamburger menu drawer when a tab is selected or Escape is pressed
const navToggle = document.getElementById('nav-drawer-toggle');
if (navToggle) {
  document.querySelectorAll('#nav [role="tab"]').forEach(tab => {
    tab.addEventListener('click', () => { navToggle.checked = false; });
  });
  addEventListener('keydown', event => {
    if (event.key === 'Escape' && navToggle.checked) {
      navToggle.checked = false;
    }
  });
}
function refreshName() {
  invalidate();
  const operation = { generation, controller: new AbortController(), timer: null };
  active = operation;
  operation.timer = setTimeout(() => { if (active === operation) invalidate(); }, 15000);
  fetch('/api/personal-ai/status', { credentials: 'omit', cache: 'no-store', signal: operation.controller.signal, redirect: 'error' })
  .then(async response => {
    if (!response.ok) return;
    const body = await response.json();
    const name = body?.data?.appName;
    if (active !== operation || generation !== operation.generation || body?.ok !== true || typeof name !== 'string' || name !== name.normalize('NFC') || [...name].length < 1 || [...name].length > 32 || name.trim() !== name || /[\p{Cc}\p{Cf}]/u.test(name)) return;
    document.title = `${name} · ZTNA & XDR`;
    const brand = document.querySelector('.brand-name');
    if (!brand) return;
    // Retain the existing subtitle element and its contents.
    for (const node of [...brand.childNodes]) {
      if (node.nodeType === Node.TEXT_NODE) node.remove();
    }
    brand.prepend(document.createTextNode(`${name} `));
  })
  .catch(() => {})
  .finally(() => { clearTimeout(operation.timer); if (active === operation) active = null; });
}
refreshName();
