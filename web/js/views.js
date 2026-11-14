// Views for the web app. Each view takes the `app` controller from /app.js.
import * as auth from '/shared/auth.js';
import { ApiError } from '/shared/client.js';
import { MIN_PASSWORD_LENGTH, deriveFromPassword, fingerprint, generatePassphrase, sealForDevice } from '/shared/crypto.js';
import { copyText, glyph, googleLogo, h, modal, relTime, toast } from '/js/ui.js';

const brand = () => h('a', { class: 'brand', href: '/' }, h('img', { src: '/icon.svg', alt: '', width: 30, height: 30 }), h('span', {}, 'u', h('b', {}, 'clip')));
const errText = (e) => (e instanceof ApiError || e?.code === 'wrong_secret' ? e.message : `Something went wrong: ${e?.message ?? e}`);

/** Wire a submit handler: disables the button, shows errors in `errEl`. */
function submit(form, btn, errEl, fn) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.hidden = true;
    const label = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Working…';
    try {
      await fn();
    } catch (err) {
      errEl.textContent = errText(err);
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  });
}

const field = (label, input, hint) => h('div', { class: 'field' }, h('label', { for: input.id, text: label }), input, hint ? h('div', { class: 'hint', text: hint }) : null);
const input = (id, type, props = {}) => h('input', { id, name: id, type, required: true, ...props });

function showPasswordToggle(...inputs) {
  return h('label', { class: 'toggles' }, h('input', { type: 'checkbox', onchange: (e) => inputs.forEach((i) => (i.type = e.target.checked ? 'text' : 'password')) }), 'Show');
}

// ---------------------------------------------------------------------------------------------- auth

export function authView(app, mode = 'login', { notice, error } = {}) {
  const card = h('div', { class: 'auth-card' });
  const wrap = h('div', { class: 'center-page' }, card);

  function render() {
    const signup = mode === 'signup';
    const email = input('email', 'email', { autocomplete: 'username', placeholder: 'you@example.com', autofocus: true });
    const password = input('password', 'password', { autocomplete: signup ? 'new-password' : 'current-password', minLength: signup ? MIN_PASSWORD_LENGTH : 1 });
    const invite = signup && app.providers.inviteRequired ? field('Invite code', input('invite', 'text', { autocomplete: 'off' })) : null;
    const err = h('p', { class: 'error', role: 'alert', hidden: !error, text: error ?? '' });
    const btn = h('button', { class: 'btn block', type: 'submit', text: signup ? 'Create account' : 'Sign in' });
    const form = h(
      'form',
      { novalidate: false },
      field('Email', email),
      field('Password', password, signup ? `At least ${MIN_PASSWORD_LENGTH} characters. It encrypts your clipboard on this device; we cannot reset or recover it for you.` : null),
      showPasswordToggle(password),
      invite,
      err,
      btn,
    );
    submit(form, btn, err, async () => {
      const info = { device: app.device, platform: app.platform, client: 'web' };
      if (signup) {
        const res = await auth.signup(app.api, { email: email.value, password: password.value, inviteCode: invite?.querySelector('input').value || undefined, ...info });
        return app.signedIn(res, res.vaultKey);
      }
      const res = await auth.login(app.api, { email: email.value, password: password.value, ...info });
      return app.signedIn(res, res.vaultKey);
    });

    card.replaceChildren(
      ...[
      brand(),
      h('h1', { text: signup ? 'Create your account' : 'Welcome back' }),
      h('p', { class: 'sub', text: signup ? 'One account, every device. Takes a minute.' : 'Sign in to sync your clipboard.' }),
      notice ? h('div', { class: 'notice', text: notice }) : null,
      !app.providers.signups && signup ? h('div', { class: 'notice warn', text: 'New sign-ups are closed on this server.' }) : null,
      h(
        'div',
        { class: 'seg', role: 'tablist' },
        h('button', { role: 'tab', type: 'button', 'aria-selected': String(!signup), text: 'Sign in', onclick: () => ((mode = 'login'), history.replaceState(null, '', '/login'), render()) }),
        h('button', { role: 'tab', type: 'button', 'aria-selected': String(signup), text: 'Create account', onclick: () => ((mode = 'signup'), history.replaceState(null, '', '/signup'), render()) }),
      ),
      app.providers.google ? [h('a', { class: 'btn ghost block', href: '/api/v1/auth/google/start' }, googleLogo(), 'Continue with Google'), h('div', { class: 'divider', text: 'or with email' })] : null,
      form,
      !signup ? h('p', { class: 'hint' }, h('a', { class: 'linkish', href: '/forgot', onclick: (e) => (e.preventDefault(), app.go('/forgot')), text: 'Forgot your password?' })) : null,
      ].flat().filter(Boolean),
    );
    email.focus();
  }
  render();
  return wrap;
}

export function unlockView(app) {
  const isPassword = app.wrap.kind === 'password';
  const secret = input('secret', 'password', { autocomplete: isPassword ? 'current-password' : 'off', autofocus: true });
  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  const btn = h('button', { class: 'btn block', type: 'submit', text: 'Unlock' });
  const form = h('form', {}, field(isPassword ? 'Password' : 'Clipboard passphrase', secret, isPassword ? undefined : 'The passphrase you created the first time you signed in with Google.'), showPasswordToggle(secret), err, btn);
  submit(form, btn, err, async () => app.useKey(await auth.unlock(app.wrap, app.user, secret.value)));
  return h(
    'div',
    { class: 'center-page' },
    h(
      'div',
      { class: 'auth-card' },
      brand(),
      h('h1', { text: 'Unlock your clipboard' }),
      h('p', { class: 'sub', text: `Signed in as ${app.user.email}. Your clipboard is end-to-end encrypted, so this browser needs your ${isPassword ? 'password' : 'clipboard passphrase'} once.` }),
      form,
      h('p', { class: 'hint' }, h('button', { class: 'linkish', type: 'button', text: 'Sign out', onclick: () => app.signOut() })),
    ),
  );
}

export function createPassphraseView(app) {
  let pass = generatePassphrase();
  const box = h('div', { class: 'passphrase', text: pass });
  const saved = h('input', { type: 'checkbox', id: 'saved' });
  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  const btn = h('button', { class: 'btn block', type: 'submit', text: 'Continue' });
  const form = h('form', {}, box, h('div', { class: 'row' }, h('button', { class: 'btn small ghost', type: 'button', text: 'Copy', onclick: async () => toast((await copyText(pass)) ? 'Copied' : 'Select and copy it manually') }), h('button', { class: 'btn small ghost', type: 'button', text: 'New one', onclick: () => ((pass = generatePassphrase()), (box.textContent = pass)) })), h('div', { class: 'toggles' }, h('label', {}, saved, 'I saved it somewhere safe')), err, btn);
  submit(form, btn, err, async () => {
    if (!saved.checked) throw new Error('Tick the box once you have saved the passphrase.');
    const { wrap, authKey, vaultKey } = await auth.createPassphraseWrap(app.user, pass);
    await app.api.call('POST', '/api/v1/account/key', { wrap, authKey });
    app.wrap = wrap;
    await app.useKey(vaultKey);
  });
  return h(
    'div',
    { class: 'center-page' },
    h('div', { class: 'auth-card' }, brand(), h('h1', { text: 'Create your clipboard passphrase' }), h('p', { class: 'sub', text: 'Google does not give us a password to encrypt with, so your clipboard is locked with this passphrase instead. You enter it once on each new device. We cannot recover it.' }), form),
  );
}

export function forgotView(app) {
  const email = input('email', 'email', { autocomplete: 'username', autofocus: true });
  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  const btn = h('button', { class: 'btn block', type: 'submit', text: 'Send reset link' });
  const card = h('div', { class: 'auth-card' });
  const form = h('form', {}, field('Email', email), err, btn);
  submit(form, btn, err, async () => {
    await app.api.call('POST', '/api/v1/auth/forgot', { email: email.value });
    card.replaceChildren(brand(), h('h1', { text: 'Check your inbox' }), h('p', { class: 'sub', text: 'If an account exists for that address, a reset link is on its way. It works once and expires in an hour.' }), h('a', { class: 'btn ghost block', href: '/login', onclick: (e) => (e.preventDefault(), app.go('/login')), text: 'Back to sign in' }));
  });
  card.append(brand(), h('h1', { text: 'Reset your password' }), h('p', { class: 'sub', text: 'We will email you a link to choose a new one.' }), form, h('div', { class: 'notice warn' }, 'Because your clipboard is encrypted with your password, a reset deletes the existing clipboard history. Your account and devices keep working.'));
  return h('div', { class: 'center-page' }, card);
}

export function resetView(app, token) {
  const card = h('div', { class: 'auth-card' }, brand(), h('p', { class: 'sub', text: 'Checking your link…' }));
  const bad = (msg) => card.replaceChildren(brand(), h('h1', { text: 'Link not valid' }), h('p', { class: 'sub', text: msg }), h('a', { class: 'btn block', href: '/forgot', onclick: (e) => (e.preventDefault(), app.go('/forgot')), text: 'Request a new link' }));
  if (!token) bad('This reset link is incomplete.');
  else
    app.api.call('POST', '/api/v1/auth/reset/inspect', { token }).then(({ email }) => {
      const pw = input('password', 'password', { autocomplete: 'new-password', minLength: MIN_PASSWORD_LENGTH, autofocus: true });
      const err = h('p', { class: 'error', role: 'alert', hidden: true });
      const btn = h('button', { class: 'btn block', type: 'submit', text: 'Set new password' });
      const form = h('form', {}, field('New password', pw, `At least ${MIN_PASSWORD_LENGTH} characters.`), showPasswordToggle(pw), err, btn);
      submit(form, btn, err, async () => {
        await app.api.call('POST', '/api/v1/auth/reset', { token, ...(await auth.resetBody(email, pw.value)) });
        toast('Password updated. Sign in with it.');
        await app.go('/login');
      });
      card.replaceChildren(brand(), h('h1', { text: 'Choose a new password' }), h('p', { class: 'sub', text: `For ${email}. Existing clipboard history will be deleted.` }), form);
    }, () => bad('This link is invalid or has expired.'));
  return h('div', { class: 'center-page' }, card);
}

export async function verifyScreen(app, token) {
  const card = h('div', { class: 'auth-card' }, brand(), h('p', { class: 'sub', text: 'Confirming your email…' }));
  app.mount(h('div', { class: 'center-page' }, card));
  try {
    if (!token) throw new Error('This link is incomplete.');
    await app.api.call('POST', '/api/v1/auth/verify', { token });
    card.replaceChildren(brand(), h('h1', { text: 'Email confirmed ✓' }), h('p', { class: 'sub', text: 'You are all set. Open your clipboard to start syncing.' }), h('a', { class: 'btn block', href: '/app', onclick: (e) => (e.preventDefault(), app.go('/app')), text: 'Open uclip' }));
  } catch (e) {
    card.replaceChildren(brand(), h('h1', { text: 'Link not valid' }), h('p', { class: 'sub', text: errText(e) }), h('a', { class: 'btn ghost block', href: '/app', onclick: (ev) => (ev.preventDefault(), app.go('/app')), text: 'Continue' }));
  }
}

// ---------------------------------------------------------------------------------------------- main

function guessPlatform(name, sessions) {
  const s = sessions.find((x) => x.device === name);
  if (s) return s.platform;
  return /windows|\bwin/i.test(name) ? 'windows' : /android|termux|pixel|galaxy|phone/i.test(name) ? 'android' : /linux|ubuntu|debian|arch|fedora/i.test(name) ? 'linux' : /mac|darwin/i.test(name) ? 'macos' : /browser|chrome|firefox|safari|edge/i.test(name) ? 'web' : 'other';
}

export function mainView(app) {
  const live = h('span', { class: 'live', role: 'status' }, h('i'), h('span', { text: 'Connecting…' }));
  const avatar = h('button', { class: 'avatar', type: 'button', 'aria-label': 'Account and settings', text: (app.user.email[0] ?? '?').toUpperCase(), onclick: () => settingsModal(app) });
  const header = h('header', { class: 'app-head' }, brand(), h('span', { class: 'spacer' }), live, avatar);

  const text = h('textarea', { id: 'text', rows: 3, placeholder: 'Paste or type here, or press Ctrl+V anywhere on this page. It lands on every device you are signed in on.', 'aria-label': 'Text to send' });
  const composer = h('form', { class: 'composer' });
  const sendBtn = h('button', { class: 'btn small', type: 'submit', text: 'Send' });
  const doSend = async (value) => {
    if (!value || app.needsVerify) return;
    try {
      await app.send(value);
      app.lastClip = value;
      text.value = '';
    } catch (e) {
      if (!(await app.handleAuthError(e))) toast(errText(e));
    }
  };
  composer.append(
    text,
    h(
      'div',
      { class: 'tools' },
      h('span', { class: 'hint', text: 'Ctrl+Enter to send' }),
      h('button', { class: 'btn small ghost', type: 'button', text: 'Paste & send', onclick: async () => {
        try {
          await doSend(await navigator.clipboard.readText());
        } catch {
          toast('Your browser blocked clipboard access. Paste into the box instead.');
        }
      } }),
      sendBtn,
    ),
  );
  composer.addEventListener('submit', (e) => (e.preventDefault(), doSend(text.value)));
  text.addEventListener('keydown', (e) => (e.ctrlKey || e.metaKey) && e.key === 'Enter' && (e.preventDefault(), doSend(text.value)));
  composer.addEventListener('dragover', (e) => (e.preventDefault(), composer.classList.add('drag')));
  composer.addEventListener('dragleave', () => composer.classList.remove('drag'));
  composer.addEventListener('drop', (e) => {
    e.preventDefault();
    composer.classList.remove('drag');
    doSend(e.dataTransfer.getData('text'));
  });

  const auto = h('input', { type: 'checkbox', checked: app.prefs.auto.get(), onchange: (e) => app.prefs.auto.set(e.target.checked) });
  const capture = h('input', { type: 'checkbox', checked: app.prefs.capture.get(), onchange: (e) => {
    app.prefs.capture.set(e.target.checked);
    if (e.target.checked) app.captureClipboard({ baselineOnly: true }); // asks for permission; what is on the clipboard now is not sent
  } });
  const toggles = h('div', { class: 'toggles' }, h('label', {}, auto, 'Auto-copy incoming clips'), h('label', {}, capture, 'Capture what I copy when I return to this tab'));

  const banner = h('div', { class: 'notice warn', hidden: true }, h('strong', { text: 'Confirm your email to start syncing. ' }), 'We sent a link to ', h('b', { text: app.user.email }), '. ', h('button', { class: 'linkish', type: 'button', text: 'Resend', onclick: async () => {
    try {
      await app.api.call('POST', '/api/v1/auth/verify/resend');
      toast('Sent');
    } catch (e) {
      toast(errText(e));
    }
  } }), ' · ', h('button', { class: 'linkish', type: 'button', text: 'I have confirmed it', onclick: () => app.start() }));

  const tape = h('ul', { class: 'tape', 'aria-label': 'Clipboard history' });
  const devices = h('ul', { class: 'devs' });

  const side = h(
    'aside',
    { class: 'side' },
    h('div', { class: 'panel-card' }, h('h3', { text: 'Signed-in devices' }), devices, h('button', { class: 'btn small block', type: 'button', text: '+ Add a device', onclick: () => addDeviceModal(app) })),
    h('div', { class: 'panel-card' }, h('h3', { text: 'Session-only' }), h('p', { class: 'hint', text: 'Only devices with an active session send or receive clips. Sign a device out and it stops immediately.' })),
  );

  const ui = {
    setDraft(value) {
      text.value = value;
      text.focus();
    },
    renderStatus() {
      const online = app.sessions.filter((s) => s.online).length;
      live.className = `live ${app.status === 'online' ? 'on' : 'bad'}`;
      live.lastChild.textContent = app.status === 'online' ? `Live · ${Math.max(online, 1)} online` : 'Reconnecting…';
    },
    renderDevices() {
      devices.replaceChildren(
        ...app.sessions.map((s) =>
          h(
            'li',
            {},
            h('span', { class: `dot ${s.online ? 'on' : ''}`, title: s.online ? 'online' : 'offline' }),
            h('span', { class: 'name', title: s.device, text: `${glyph(s.platform)} ${s.device}` }),
            s.current ? h('span', { class: 'you', text: 'YOU' }) : h('button', { class: 'btn small ghost', type: 'button', title: `Sign out ${s.device}`, 'aria-label': `Sign out ${s.device}`, text: 'Sign out', onclick: async () => {
              await app.client.revokeSession(s.id).catch((e) => toast(errText(e)));
              app.refreshSessions();
            } }),
            s.current || s.online ? null : h('span', { class: 'meta', text: relTime(s.lastSeen) }),
          ),
        ),
      );
      ui.renderStatus();
    },
    renderTape(freshId) {
      banner.hidden = !app.needsVerify;
      sendBtn.disabled = text.disabled = app.needsVerify;
      if (!app.items.length) {
        tape.replaceChildren(h('li', { class: 'empty' }, h('b', { text: app.needsVerify ? 'Waiting for email confirmation' : 'Nothing on the tape yet' }), app.needsVerify ? 'Confirm your email address to start syncing.' : 'Copy something on another signed-in device, or send something from here.'));
        return;
      }
      tape.replaceChildren(
        ...[...app.items].reverse().map((item) => {
          const platform = guessPlatform(item.device, app.sessions);
          const copy = h('button', { class: 'btn small', type: 'button', text: 'Copy', onclick: async () => {
            copy.textContent = (await copyText(item.text)) ? 'Copied ✓' : 'Failed';
            setTimeout(() => (copy.textContent = 'Copy'), 1200);
          } });
          return h(
            'li',
            { class: `clip ${item.id === freshId ? 'fresh' : ''}` },
            h('div', { class: 'stub' }, h('span', { class: 'glyph', text: glyph(platform) }), h('span', { class: 'dev-name', title: item.device, text: item.device }), h('span', { class: 'when', text: relTime(item.ts) })),
            h('div', { class: 'main' }, h('pre', { text: item.text }), h('div', { class: 'actions' }, copy, h('button', { class: 'btn small ghost', type: 'button', text: 'Delete', onclick: () => app.client.remove(item.id).catch((e) => toast(errText(e))) }))),
          );
        }),
      );
    },
  };
  app.ui = ui;
  ui.renderDevices();
  ui.renderTape();

  return h('div', {}, header, h('div', { class: 'workspace' }, h('main', {}, banner, composer, toggles, tape), side));
}

// ---------------------------------------------------------------------------------------------- modals

export function settingsModal(app) {
  const { user } = app;
  const m = modal();
  const section = (title, ...kids) => h('section', {}, h('h3', { text: title }), ...kids);
  const msg = () => h('p', { class: 'error', role: 'alert', hidden: true });
  const body = [h('h2', { text: 'Account' }), h('p', { class: 'dim', text: `${user.email}${user.google ? ' · Google' : ''}${user.hasPassword ? ' · password' : ''}` })];

  // Change password (password accounts) or clipboard passphrase (Google-only accounts)
  {
    const err = msg();
    const isPw = user.hasPassword;
    const oldI = input('old', 'password', { autocomplete: isPw ? 'current-password' : 'off' });
    const newI = input('new', 'password', { autocomplete: 'new-password', minLength: MIN_PASSWORD_LENGTH });
    const btn = h('button', { class: 'btn small', type: 'submit', text: isPw ? 'Change password' : 'Change passphrase' });
    const form = h('form', {}, field(isPw ? 'Current password' : 'Current passphrase', oldI), field(isPw ? 'New password' : 'New passphrase', newI, isPw ? 'Other devices are signed out when you change it.' : `At least ${MIN_PASSWORD_LENGTH} characters. Pick something long, or press Generate.`), !isPw ? h('button', { class: 'btn small ghost', type: 'button', text: 'Generate', onclick: () => ((newI.type = 'text'), (newI.value = generatePassphrase())) }) : null, err, btn);
    submit(form, btn, err, async () => {
      if (isPw) await app.api.call('POST', '/api/v1/account/password', await auth.passwordChangeBody(user, app.wrap, oldI.value, newI.value));
      else {
        const next = await auth.passphraseChangeBody(user, app.wrap, oldI.value, newI.value);
        await app.api.call('POST', '/api/v1/account/key', next);
        app.wrap = next.wrap;
      }
      oldI.value = newI.value = '';
      toast('Updated');
      if (isPw) app.wrap = (await app.client.account()).wrap;
      app.refreshSessions();
    });
    body.push(section(isPw ? 'Password' : 'Clipboard passphrase', form));
  }

  body.push(
    section(
      'Clipboard',
      h('div', { class: 'row' },
        h('button', { class: 'btn small ghost', type: 'button', text: 'Clear all items', onclick: async () => {
          if (confirm('Delete every clipboard item on every device?')) {
            await app.client.clear();
            toast('Cleared');
          }
        } }),
        h('button', { class: 'btn small ghost', type: 'button', text: 'Sign out other devices', onclick: async () => {
          await app.api.call('DELETE', '/api/v1/sessions');
          app.refreshSessions();
          toast('Other devices signed out');
        } }),
      ),
    ),
  );

  // Delete account
  {
    const err = msg();
    const emailI = input('confirm', 'text', { autocomplete: 'off', placeholder: user.email });
    const pwI = field(user.hasPassword ? 'Password' : 'Clipboard passphrase', input('pw', 'password', { autocomplete: 'current-password' }));
    const btn = h('button', { class: 'btn small danger', type: 'submit', text: 'Delete my account' });
    const form = h('form', {}, h('p', { class: 'hint', text: 'Removes your account, devices and clipboard data from the server. This cannot be undone.' }), field('Type your email to confirm', emailI), pwI, err, btn);
    submit(form, btn, err, async () => {
      const body = { confirmEmail: emailI.value };
      const secret = pwI.querySelector('input').value;
      body.authKey = user.hasPassword ? (await deriveFromPassword(secret, user.email)).authKey : await auth.passphraseAuthKey(user, secret);
      await app.api.call('POST', '/api/v1/account/delete', body);
      m.close();
      await app.sessionEnded('Your account was deleted.');
    });
    body.push(section('Delete account', form));
  }

  body.push(h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', text: 'Sign out', onclick: () => (m.close(), app.signOut()) }), h('span', { class: 'spacer' }), h('button', { class: 'btn ghost', type: 'button', text: 'Close', onclick: m.close })));
  m.el.append(...body);
}

export function addDeviceModal(app) {
  const code = h('input', { id: 'code', name: 'code', type: 'text', placeholder: 'ABCD-EFGH', autocomplete: 'off', autocapitalize: 'characters', class: 'mono' });
  const m = modal(
    h('h2', { text: 'Add a device' }),
    h('p', { class: 'dim', text: 'Another browser: just sign in to this site there. For a computer or phone running the uclip app:' }),
    h('ol', {}, h('li', {}, 'On that device run ', h('code', { text: 'uclip login' }), '.'), h('li', {}, 'It shows a short code. Type it here.'), h('li', {}, 'Confirm with your password. Done; copy as usual.')),
    h('form', { onsubmit: (e) => {
      e.preventDefault();
      if (!code.value.trim()) return;
      m.close();
      approveModal(app, code.value);
    } }, field('Code shown on the device', code), h('div', { class: 'row' }, h('button', { class: 'btn', type: 'submit', text: 'Continue' }), h('button', { class: 'btn ghost', type: 'button', text: 'Cancel', onclick: () => m.close() }))),
  );
}

export function approveModal(app, initialCode = '') {
  const m = modal();
  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  const fail = (e) => {
    err.textContent = e instanceof ApiError && e.status === 404 ? 'No waiting device has that code. Check it and try again (codes expire after 10 minutes).' : errText(e);
    err.hidden = false;
  };

  function lookup(code) {
    const codeI = h('input', { id: 'code', name: 'code', type: 'text', value: code, placeholder: 'ABCD-EFGH', autocomplete: 'off', class: 'mono' });
    const btn = h('button', { class: 'btn', type: 'submit', text: 'Look up' });
    const form = h('form', {}, field('Code shown on the device', codeI), err, h('div', { class: 'row' }, btn, h('button', { class: 'btn ghost', type: 'button', text: 'Cancel', onclick: m.close })));
    submit(form, btn, err, async () => confirmStep(await app.api.call('POST', '/api/v1/device/lookup', { userCode: codeI.value })));
    m.el.replaceChildren(h('h2', { text: 'Approve a device' }), form);
    codeI.focus();
  }

  async function confirmStep(req) {
    const fp = await fingerprint(req.pub);
    const isPw = app.wrap?.kind === 'password';
    const secret = input('secret', 'password', { autocomplete: isPw ? 'current-password' : 'off' });
    const err2 = h('p', { class: 'error', role: 'alert', hidden: true });
    const btn = h('button', { class: 'btn', type: 'submit', text: 'Approve' });
    const form = h('form', {}, field(isPw ? 'Confirm with your password' : 'Confirm with your clipboard passphrase', secret), err2, h('div', { class: 'row' }, btn, h('button', { class: 'btn danger', type: 'button', text: 'Deny', onclick: async () => {
      await app.api.call('POST', '/api/v1/device/approve', { userCode: req.userCode, deny: true }).catch(() => {});
      m.close();
    } })));
    submit(form, btn, err2, async () => {
      const raw = await auth.unlock(app.wrap, app.user, secret.value);
      const sealed = await sealForDevice(req.pub, raw);
      await app.api.call('POST', '/api/v1/device/approve', { userCode: req.userCode, sealed });
      m.close();
      toast(`${req.device} is signed in`);
      app.refreshSessions();
    });
    m.el.replaceChildren(
      h('h2', { text: 'Approve this device?' }),
      h('div', { class: 'code-big', text: req.userCode }),
      h('p', { class: 'hint' }, 'Key check: ', h('b', { class: 'mono', text: fp }), '. It must match the “Key check” your device printed. If it does not, deny.'),
      h('p', {}, glyph(req.platform), ' ', h('b', { text: req.device }), ` (${req.platform}) is asking to sign in as `, h('b', { text: app.user.email }), '.'),
      h('div', { class: 'notice warn', text: 'Only approve if this exact code is showing on a device you started the login on. Approving gives it access to your clipboard.' }),
      form,
    );
    secret.focus();
  }

  lookup(initialCode);
  if (initialCode) m.el.querySelector('form').requestSubmit();
}
