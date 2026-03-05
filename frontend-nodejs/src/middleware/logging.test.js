const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { errorLogger } = require('./logging');

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

test('errorLogger does not leak raw internal 500 error messages', async () => {
  const app = express();
  app.get('/boom', (req, res, next) => {
    next(new Error('Database connection string is invalid: postgres://secret'));
  });
  app.use(errorLogger);

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/boom`);
    const body = await response.json();

    assert.equal(response.status, 500);
    assert.equal(body.error, 'internal_error');
    assert.equal(body.message, 'Internal server error');
    assert.ok(!String(body.message).includes('postgres://secret'));
  });
});

test('errorLogger allows explicit safe publicMessage for 4xx', async () => {
  const app = express();
  app.get('/bad-request', (req, res, next) => {
    const err = new Error('SQL syntax error near user_input');
    err.status = 400;
    err.publicMessage = 'Invalid request payload';
    next(err);
  });
  app.use(errorLogger);

  await withServer(app, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/bad-request`);
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'request_failed');
    assert.equal(body.message, 'Invalid request payload');
  });
});

test('errorLogger production logging omits stack and raw internal message', async () => {
  const previousNodeEnv = process.env.NODE_ENV;
  const originalConsoleError = console.error;
  process.env.NODE_ENV = 'production';

  const capturedLogs = [];
  console.error = (...args) => {
    capturedLogs.push(args);
  };

  try {
    const app = express();
    app.get('/prod-boom', (req, res, next) => {
      next(new Error('Sensitive backend detail should not be logged in production'));
    });
    app.use(errorLogger);

    await withServer(app, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/prod-boom`);
      const body = await response.json();

      assert.equal(response.status, 500);
      assert.equal(body.error, 'internal_error');
      assert.equal(body.message, 'Internal server error');
    });

    const serialized = JSON.stringify(capturedLogs);
    assert.ok(serialized.includes('statusCode'));
    assert.ok(!serialized.includes('stack'));
    assert.ok(!serialized.includes('Sensitive backend detail should not be logged in production'));
  } finally {
    process.env.NODE_ENV = previousNodeEnv;
    console.error = originalConsoleError;
  }
});
