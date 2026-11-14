// Landing page: OS tabs and copy buttons.
const tabs = [...document.querySelectorAll('.tab')];
for (const tab of tabs) {
  tab.addEventListener('click', () => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    }
  });
}

// Preselect the tab for the visitor's OS.
const ua = navigator.userAgent;
const guess = /Android/.test(ua) ? 't-android' : /Windows/.test(ua) ? 't-win' : null;
if (guess) document.getElementById(guess)?.click();

for (const btn of document.querySelectorAll('[data-copy]')) {
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(btn.previousElementSibling.textContent);
      btn.textContent = 'Copied';
    } catch {
      btn.textContent = 'Select & copy';
    }
    setTimeout(() => (btn.textContent = 'Copy'), 1500);
  });
}
