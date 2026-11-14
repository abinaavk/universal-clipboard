// Transactional email. Uses the Resend HTTP API when configured; otherwise mails are logged (and kept in
// `outbox`, which the tests read) so local development works without any provider.
export function createMailer(cfg) {
  const outbox = [];
  async function send({ to, subject, text }) {
    outbox.push({ to, subject, text });
    if (outbox.length > 50) outbox.shift();
    if (!cfg.mail.resendApiKey) {
      if (cfg.logMail) console.log(`[mail:not-sent] to=${to} subject="${subject}"\n${text}\n`);
      return;
    }
    const res = await fetch(cfg.mail.apiUrl, {
      method: 'POST',
      headers: { authorization: `Bearer ${cfg.mail.resendApiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from: cfg.mail.from, to: [to], subject, text }),
    });
    if (!res.ok) throw new Error(`mail provider -> ${res.status} ${(await res.text().catch(() => '')).slice(0, 200)}`);
  }
  return { send, outbox };
}

export const verifyMail = (url) => ({
  subject: 'Confirm your Universal Clipboard email',
  text: `Welcome to Universal Clipboard.\n\nConfirm your email address to start syncing:\n${url}\n\nThe link works once and expires in 24 hours. If you did not create an account, ignore this email.\n`,
});

export const resetMail = (url) => ({
  subject: 'Reset your Universal Clipboard password',
  text: `Someone asked to reset the password for this account.\n\nChoose a new password here:\n${url}\n\nThe link works once and expires in 1 hour. If it was not you, ignore this email; your password stays as it is.\n\nNote: your clipboard is end-to-end encrypted with a key derived from your password. A reset cannot recover old clipboard items, so they are deleted. Your account and devices keep working.\n`,
});
