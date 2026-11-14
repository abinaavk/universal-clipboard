// OpenAPI 3.1 description of the public HTTP API, served at /api/v1/openapi.json and rendered at /docs.
export function buildOpenApi(cfg) {
  const json = (schema, description = 'OK') => ({ description, content: { 'application/json': { schema } } });
  const body = (schema) => ({ required: true, content: { 'application/json': { schema } } });
  const obj = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required });
  const str = { type: 'string' };
  const wrap = { $ref: '#/components/schemas/Wrap' };
  const err = { $ref: '#/components/responses/Error' };
  const secured = [{ bearer: [] }, { cookie: [] }];
  const op = (tag, summary, extra = {}) => ({ tags: [tag], summary, ...extra });

  return {
    openapi: '3.1.0',
    info: {
      title: 'Universal Clipboard API',
      version: '1.0.0',
      description:
        'HTTP API of the Universal Clipboard relay. All clipboard content is end-to-end encrypted by the clients; the server only ever handles accounts, device sessions and ciphertext. ' +
        'Browsers authenticate with an HttpOnly session cookie (and must send `x-uc-csrf: 1` on non-GET requests); devices and scripts use `Authorization: Bearer <token>` obtained from the device flow or `/auth/login`.',
      license: { name: 'MIT', identifier: 'MIT' },
      contact: { url: cfg.publicUrl },
    },
    servers: [{ url: cfg.publicUrl }],
    tags: [{ name: 'Auth' }, { name: 'Account' }, { name: 'Devices' }, { name: 'Clipboard' }, { name: 'Meta' }],
    paths: {
      '/api/v1/auth/providers': { get: op('Auth', 'Which sign-in options this server offers', { security: [], responses: { 200: json(obj({ google: { type: 'boolean' }, signups: { type: 'boolean' }, inviteRequired: { type: 'boolean' }, emailVerification: { type: 'boolean' } })) } }) },
      '/api/v1/auth/signup': { post: op('Auth', 'Create an account (email + password)', { security: [], description: '`authKey` and `wrap` are produced client-side; the password never leaves the device.', requestBody: body(obj({ email: str, authKey: { type: 'string', pattern: '^[0-9a-f]{64}$' }, wrap, device: str, platform: str, client: { enum: ['web', 'cli'] }, inviteCode: str }, ['email', 'authKey', 'wrap'])), responses: { 201: json({ $ref: '#/components/schemas/SignedIn' }), 409: err, 429: err } }) },
      '/api/v1/auth/login': { post: op('Auth', 'Sign in with email + password', { security: [], requestBody: body(obj({ email: str, authKey: str, device: str, platform: str, client: { enum: ['web', 'cli'] } }, ['email', 'authKey'])), responses: { 200: json({ $ref: '#/components/schemas/SignedIn' }), 401: err, 429: err } }) },
      '/api/v1/auth/logout': { post: op('Auth', 'End the current session', { security: [], responses: { 204: { description: 'Signed out' } } }) },
      '/api/v1/auth/verify': { post: op('Auth', 'Confirm an email address', { security: [], requestBody: body(obj({ token: str })), responses: { 200: json(obj({ user: { $ref: '#/components/schemas/User' } })), 400: err } }) },
      '/api/v1/auth/verify/resend': { post: op('Auth', 'Resend the confirmation email', { security: secured, responses: { 202: { description: 'Queued' } } }) },
      '/api/v1/auth/forgot': { post: op('Auth', 'Email a password-reset link', { security: [], description: 'Always answers 202 so account existence is not revealed.', requestBody: body(obj({ email: str })), responses: { 202: { description: 'Accepted' } } }) },
      '/api/v1/auth/reset/inspect': { post: op('Auth', 'Look up the email for a reset token', { security: [], requestBody: body(obj({ token: str })), responses: { 200: json(obj({ email: str })), 400: err } }) },
      '/api/v1/auth/reset': { post: op('Auth', 'Set a new password with a reset token', { security: [], description: 'Deletes existing clipboard items (they were encrypted under the old password) and ends all sessions.', requestBody: body(obj({ token: str, authKey: str, wrap })), responses: { 204: { description: 'Password reset' }, 400: err } }) },
      '/api/v1/auth/google/start': { get: op('Auth', 'Begin Google sign-in (browser redirect)', { security: [], responses: { 302: { description: 'Redirect to Google' }, 404: err } }) },
      '/api/v1/auth/google/callback': { get: op('Auth', 'Google redirect target', { security: [], responses: { 302: { description: 'Redirect to /app with a one-time ticket' } } }) },
      '/api/v1/auth/google/exchange': { post: op('Auth', 'Trade the one-time ticket for a session', { security: [], requestBody: body(obj({ ticket: str, device: str, platform: str }, ['ticket'])), responses: { 200: json({ $ref: '#/components/schemas/SignedIn' }), 400: err } }) },
      '/api/v1/account': { get: op('Account', 'Current user, wrapped vault key and session', { security: secured, responses: { 200: json(obj({ user: { $ref: '#/components/schemas/User' }, wrap: { oneOf: [wrap, { type: 'null' }] }, session: { $ref: '#/components/schemas/Session' } })), 401: err } }) },
      '/api/v1/account/key': { post: op('Account', 'Set the wrapped vault key (Google accounts, first time)', { security: secured, requestBody: body(obj({ wrap })), responses: { 204: { description: 'Stored' }, 409: err } }) },
      '/api/v1/account/password': { post: op('Account', 'Change password', { security: secured, description: 'Ends all other sessions.', requestBody: body(obj({ authKey: str, newAuthKey: str, wrap })), responses: { 204: { description: 'Changed' }, 401: err } }) },
      '/api/v1/account/delete': { post: op('Account', 'Delete the account and all data', { security: secured, requestBody: body(obj({ confirmEmail: str, authKey: str }, ['confirmEmail'])), responses: { 204: { description: 'Deleted' }, 400: err, 401: err } }) },
      '/api/v1/sessions': {
        get: op('Devices', 'List signed-in devices', { security: secured, responses: { 200: json(obj({ sessions: { type: 'array', items: { $ref: '#/components/schemas/Session' } } })) } }),
        delete: op('Devices', 'Sign out every other device', { security: secured, responses: { 204: { description: 'Done' } } }),
      },
      '/api/v1/sessions/{id}': { delete: op('Devices', 'Sign out one device', { security: secured, parameters: [{ name: 'id', in: 'path', required: true, schema: str }], responses: { 204: { description: 'Revoked; the device stops syncing immediately' }, 404: err } }) },
      '/api/v1/device/start': { post: op('Devices', 'Start the device-approval flow (CLI)', { security: [], description: 'The device sends an ephemeral ECDH P-256 public key and shows `userCode` to the user, who approves it in the web app.', requestBody: body(obj({ device: str, platform: str, pub: str }, ['pub'])), responses: { 201: json(obj({ deviceCode: str, userCode: str, verificationUrl: str, expiresIn: { type: 'integer' }, interval: { type: 'integer' } })) } }) },
      '/api/v1/device/token': { post: op('Devices', 'Poll for approval', { security: [], requestBody: body(obj({ deviceCode: str })), responses: { 200: json(obj({ token: str, user: { $ref: '#/components/schemas/User' }, session: { $ref: '#/components/schemas/Session' }, sealed: { $ref: '#/components/schemas/Sealed' } })), 400: { description: '`authorization_pending`, `access_denied` or `expired_token`', ...err } } }) },
      '/api/v1/device/lookup': { post: op('Devices', 'Look up a pending device request by code', { security: secured, requestBody: body(obj({ userCode: str })), responses: { 200: json(obj({ userCode: str, device: str, platform: str, pub: str })), 404: err } }) },
      '/api/v1/device/approve': { post: op('Devices', 'Approve (or deny) a pending device', { security: secured, description: 'The approving browser seals the vault key to the device public key; the server relays it without being able to read it.', requestBody: body(obj({ userCode: str, sealed: { $ref: '#/components/schemas/Sealed' }, deny: { type: 'boolean' } }, ['userCode'])), responses: { 204: { description: 'Done' }, 404: err } }) },
      '/api/v1/items': {
        get: op('Clipboard', 'List encrypted items', { security: secured, parameters: [{ name: 'since', in: 'query', schema: { type: 'integer' } }], responses: { 200: json(obj({ items: { type: 'array', items: { $ref: '#/components/schemas/Item' } }, lastSeq: { type: 'integer' } })) } }),
        post: op('Clipboard', 'Upload an encrypted item', { security: secured, requestBody: body(obj({ id: str, nonce: str, ct: str })), responses: { 201: json({ $ref: '#/components/schemas/Item' }), 200: json({ $ref: '#/components/schemas/Item' }, 'Duplicate id; existing item returned') } }),
        delete: op('Clipboard', 'Delete every item', { security: secured, responses: { 204: { description: 'Cleared' } } }),
      },
      '/api/v1/items/{id}': { delete: op('Clipboard', 'Delete one item', { security: secured, parameters: [{ name: 'id', in: 'path', required: true, schema: str }], responses: { 204: { description: 'Deleted' } } }) },
      '/api/v1/events': { get: op('Clipboard', 'Live stream (Server-Sent Events)', { security: secured, description: 'Events: `item`, `delete`, `sessions` (device list changed) and `session-ended` (this session was revoked; stop syncing). Resume with `Last-Event-ID` or `?since=`.', responses: { 200: { description: 'text/event-stream', content: { 'text/event-stream': { schema: str } } } } }) },
      '/healthz': { get: op('Meta', 'Liveness probe', { security: [], responses: { 200: json(obj({ ok: { type: 'boolean' } })) } }) },
    },
    components: {
      securitySchemes: {
        bearer: { type: 'http', scheme: 'bearer', description: 'Device session token (`uc_…`)' },
        cookie: { type: 'apiKey', in: 'cookie', name: 'uc_session', description: 'Browser session; non-GET requests also need `x-uc-csrf: 1`' },
      },
      responses: { Error: { description: 'Error', content: { 'application/json': { schema: obj({ error: str, message: str }) } } } },
      schemas: {
        Wrap: obj({ kind: { enum: ['password', 'passphrase'] }, nonce: str, ct: str }),
        Sealed: obj({ pub: str, nonce: str, ct: str }),
        User: obj({ id: str, email: str, emailVerified: { type: 'boolean' }, hasPassword: { type: 'boolean' }, google: { type: 'boolean' }, name: str }, ['id', 'email', 'emailVerified', 'hasPassword', 'google']),
        Session: obj({ id: str, device: str, platform: str, client: str, createdAt: { type: 'integer' }, lastSeen: { type: 'integer' }, expiresAt: { type: 'integer' }, current: { type: 'boolean' }, online: { type: 'boolean' } }),
        SignedIn: obj({ user: { $ref: '#/components/schemas/User' }, wrap: { oneOf: [wrap, { type: 'null' }] }, session: { $ref: '#/components/schemas/Session' }, token: str }, ['user', 'wrap', 'session']),
        Item: obj({ id: str, seq: { type: 'integer' }, ts: { type: 'integer' }, nonce: str, ct: str }),
      },
    },
  };
}
