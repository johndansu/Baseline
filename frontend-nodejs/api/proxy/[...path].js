const { Readable } = require('stream');

function normalizeAPIOrigin() {
  const raw = String(process.env.BASELINE_API_ORIGIN || '').trim();
  if (!raw) {
    throw new Error('BASELINE_API_ORIGIN is required for Vercel API proxy');
  }
  return raw.replace(/\/+$/, '');
}

function buildTargetURL(req) {
  const origin = normalizeAPIOrigin();
  const pathSegments = Array.isArray(req.query.path)
    ? req.query.path
    : [req.query.path].filter(Boolean);
  const pathname = `/${pathSegments.map((segment) => encodeURIComponent(String(segment))).join('/')}`;
  const url = new URL(origin + pathname);

  const query = { ...req.query };
  delete query.path;
  for (const [key, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        url.searchParams.append(key, String(item));
      }
      continue;
    }
    if (typeof value !== 'undefined') {
      url.searchParams.set(key, String(value));
    }
  }

  return url;
}

function filterProxyRequestHeaders(headers, host) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const normalized = String(key).toLowerCase();
    if (
      normalized === 'host' ||
      normalized === 'connection' ||
      normalized === 'content-length' ||
      normalized === 'x-forwarded-host' ||
      normalized === 'x-forwarded-proto' ||
      normalized === 'x-forwarded-port'
    ) {
      continue;
    }
    if (typeof value !== 'undefined') {
      out[key] = value;
    }
  }
  out['X-Forwarded-Host'] = host;
  out['X-Forwarded-Proto'] = 'https';
  out['X-Forwarded-Port'] = '443';
  return out;
}

function applyProxyResponseHeaders(res, upstreamHeaders) {
  const hopByHop = new Set([
    'connection',
    'content-length',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade'
  ]);

  upstreamHeaders.forEach((value, key) => {
    if (!hopByHop.has(String(key).toLowerCase())) {
      res.setHeader(key, value);
    }
  });

  if (typeof upstreamHeaders.getSetCookie === 'function') {
    const cookies = upstreamHeaders.getSetCookie();
    if (cookies.length > 0) {
      res.setHeader('set-cookie', cookies);
    }
  }
}

async function readRequestBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return undefined;
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return undefined;
  }
  return Buffer.concat(chunks);
}

module.exports = async (req, res) => {
  try {
    const targetURL = buildTargetURL(req);
    const body = await readRequestBody(req);
    const headers = filterProxyRequestHeaders(req.headers, req.headers.host || '');

    const upstream = await fetch(targetURL, {
      method: req.method,
      headers,
      body,
      redirect: 'manual'
    });

    applyProxyResponseHeaders(res, upstream.headers);
    res.statusCode = upstream.status;

    if (!upstream.body) {
      res.end();
      return;
    }

    Readable.fromWeb(upstream.body).pipe(res);
  } catch (error) {
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(
      JSON.stringify({
        error: {
          code: 'proxy_error',
          message: error instanceof Error ? error.message : 'proxy request failed'
        }
      })
    );
  }
};
