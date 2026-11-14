// Tiny JSON-file persistence with secondary indexes. Fine for a personal/small deployment; swap for a real
// database before running this for thousands of users.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export function createStore(dataDir) {
  mkdirSync(dataDir, { recursive: true });
  const file = join(dataDir, 'db.json');
  const data = { users: {}, sessions: {}, items: {}, tokens: {} };
  if (existsSync(file)) Object.assign(data, JSON.parse(readFileSync(file, 'utf8')));

  // Indexes (rebuilt on load, maintained by the helpers below)
  const byEmail = new Map();
  const byGoogle = new Map();
  const byTokenHash = new Map();
  for (const u of Object.values(data.users)) {
    byEmail.set(u.email, u);
    if (u.googleSub) byGoogle.set(u.googleSub, u);
  }
  for (const s of Object.values(data.sessions)) byTokenHash.set(s.hash, s);

  let timer = null;
  function save() {
    if (timer) return;
    timer = setTimeout(flushAsync, 200);
    timer.unref?.();
  }
  let writing = false;
  let dirty = false;
  // Never throws: a full disk must not take the process down. The next save() retries.
  async function flushAsync() {
    clearTimeout(timer);
    timer = null;
    if (writing) {
      dirty = true;
      return;
    }
    writing = true;
    try {
      const tmp = file + '.tmp';
      await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
      await rename(tmp, file);
    } catch (e) {
      console.error('could not persist database:', e.message);
      dirty = true;
    } finally {
      writing = false;
      if (dirty) {
        dirty = false;
        save();
      }
    }
  }
  function flush() {
    clearTimeout(timer);
    timer = null;
    try {
      const tmp = file + '.tmp';
      writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
      renameSync(tmp, file);
    } catch (e) {
      console.error('could not persist database:', e.message);
    }
  }

  return {
    data,
    save,
    flush,
    userByEmail: (email) => byEmail.get(email),
    userByGoogle: (sub) => byGoogle.get(sub),
    userById: (id) => data.users[id],
    userCount: () => byEmail.size,
    putUser(u) {
      data.users[u.id] = u;
      byEmail.set(u.email, u);
      if (u.googleSub) byGoogle.set(u.googleSub, u);
      save();
    },
    dropUser(u) {
      delete data.users[u.id];
      byEmail.delete(u.email);
      if (u.googleSub) byGoogle.delete(u.googleSub);
      delete data.items[u.id];
      for (const s of Object.values(data.sessions)) if (s.userId === u.id) this.dropSession(s);
      for (const [h, t] of Object.entries(data.tokens)) if (t.userId === u.id) delete data.tokens[h];
      save();
    },
    sessionByHash: (hash) => byTokenHash.get(hash),
    sessionsOf: (userId) => Object.values(data.sessions).filter((s) => s.userId === userId),
    putSession(s) {
      data.sessions[s.id] = s;
      byTokenHash.set(s.hash, s);
      save();
    },
    dropSession(s) {
      delete data.sessions[s.id];
      byTokenHash.delete(s.hash);
      save();
    },
    vault(userId) {
      return (data.items[userId] ??= { nextSeq: 1, items: [] });
    },
    /** Drop expired tokens and sessions. Returns the sessions that were removed. */
    sweep(now = Date.now()) {
      for (const [h, t] of Object.entries(data.tokens)) if (t.exp < now) delete data.tokens[h];
      const expired = Object.values(data.sessions).filter((s) => s.expiresAt < now);
      for (const s of expired) this.dropSession(s);
      return expired;
    },
    close() {
      flush();
    },
  };
}
