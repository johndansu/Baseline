const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

function loadAuthRouterWithMock(mockedSupabaseModule) {
  const routePath = require.resolve('./auth');
  const supabasePath = require.resolve('../utils/supabase');

  delete require.cache[routePath];
  delete require.cache[supabasePath];
  require.cache[supabasePath] = {
    id: supabasePath,
    filename: supabasePath,
    loaded: true,
    exports: mockedSupabaseModule
  };

  return require('./auth');
}

async function withServer(app, fn) {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });

  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    await fn(baseUrl);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

test('POST /auth/signin returns generic failure message', async () => {
  const mockedSupabaseModule = {
    supabase: {
      auth: {
        signInWithPassword: async () => ({
          data: null,
          error: {
            code: 'invalid_credentials',
            status: 400,
            message: 'Invalid login credentials for john@example.com'
          }
        })
      }
    },
    getUserSession: async () => null,
    refreshAccessToken: async () => null
  };

  const router = loadAuthRouterWithMock(mockedSupabaseModule);
  const app = express();
  app.use(express.json());
  app.use('/auth', router);

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/signin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'john@example.com', password: 'bad' })
    });
    const body = await response.json();

    assert.equal(response.status, 401);
    assert.equal(body.error, 'Authentication failed');
    assert.equal(body.message, 'Authentication failed. Check your credentials and try again.');
    assert.ok(!String(body.message).includes('john@example.com'));
    assert.ok(!String(body.message).includes('Invalid login credentials'));
  });
});

test('POST /auth/reset-password always returns non-enumerating response', async () => {
  const mockedSupabaseModule = {
    supabase: {
      auth: {
        resetPasswordForEmail: async () => ({
          error: {
            code: 'user_not_found',
            status: 400,
            message: 'User not found'
          }
        })
      }
    },
    getUserSession: async () => null,
    refreshAccessToken: async () => null
  };

  const router = loadAuthRouterWithMock(mockedSupabaseModule);
  const app = express();
  app.use(express.json());
  app.use('/auth', router);

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth/reset-password`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'unknown@example.com' })
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.message, 'If an account exists for this email, a password reset email will be sent.');
    assert.ok(!String(body.message).includes('not found'));
  });
});

test('GET /auth/session uses same generic unauthorized response for missing/invalid token', async () => {
  const mockedSupabaseModule = {
    supabase: {
      auth: {}
    },
    getUserSession: async () => null,
    refreshAccessToken: async () => null
  };

  const router = loadAuthRouterWithMock(mockedSupabaseModule);
  const app = express();
  app.use(express.json());
  app.use('/auth', router);

  await withServer(app, async (baseUrl) => {
    const missingHeaderResponse = await fetch(`${baseUrl}/auth/session`);
    const missingBody = await missingHeaderResponse.json();
    assert.equal(missingHeaderResponse.status, 401);
    assert.deepEqual(missingBody, {
      error: 'Unauthorized',
      message: 'Authentication required'
    });

    const invalidHeaderResponse = await fetch(`${baseUrl}/auth/session`, {
      headers: { authorization: 'Bearer invalid-token' }
    });
    const invalidBody = await invalidHeaderResponse.json();
    assert.equal(invalidHeaderResponse.status, 401);
    assert.deepEqual(invalidBody, {
      error: 'Unauthorized',
      message: 'Authentication required'
    });
  });
});
