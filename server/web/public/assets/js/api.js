// Thin JSON client for the BookBeam API. All URLs are relative so the app
// works under any sub-path (e.g. /books/). Every request carries the
// X-BookBeam CSRF header the server requires on mutations.

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status; // 0 = network failure or timeout
    this.body = body;
  }

  get offline() {
    return this.status === 0;
  }

  /** Worth retrying later (network trouble or server hiccup). */
  get transient() {
    return this.status === 0 || this.status === 408 || this.status === 429 || this.status >= 500;
  }
}

let unauthorizedHandler = null;

/** Called once with every 401 so the app can fall back to the login screen. */
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

/**
 * request(method, path, options) → parsed JSON (or null for empty bodies).
 * options: body (JSON-encoded), headers, timeout (ms, default 15 s),
 * keepalive (survives page unload; retried once without it if the browser
 * refuses), raw (resolve {status, data, etag}
 * instead, and treat 304 as success), quiet401 (don't trigger logout).
 */
export async function request(method, path, options) {
  const opts = options || {};
  const headers = { 'X-BookBeam': '1', Accept: 'application/json' };
  if (opts.headers) Object.keys(opts.headers).forEach((k) => (headers[k] = opts.headers[k]));
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store' };
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  if (opts.keepalive) init.keepalive = true;

  const ctrl = typeof AbortController === 'function' ? new AbortController() : null;
  const timeout = opts.timeout === undefined ? 15000 : opts.timeout;
  let timer = 0;
  if (ctrl) {
    init.signal = ctrl.signal;
    if (timeout > 0) timer = setTimeout(() => ctrl.abort(), timeout);
  }

  let res;
  try {
    try {
      res = await fetch(path, init);
    } catch (e) {
      // Chromium ≤ 80 rejects keepalive requests with custom headers outright
      // ('Failed to fetch') although the network is fine: try a plain one.
      if (!init.keepalive || (ctrl && ctrl.signal.aborted)) throw e;
      delete init.keepalive;
      res = await fetch(path, init);
    }
  } catch (e) {
    clearTimeout(timer);
    throw new ApiError(0, ctrl && ctrl.signal.aborted ? 'The server took too long to answer.' : 'Can’t reach the server.', null);
  }

  let data = null;
  try {
    const text = await res.text();
    data = text ? JSON.parse(text) : null;
  } catch (e) {
    data = null; // non-JSON body (or body interrupted); status still tells the story
  } finally {
    clearTimeout(timer);
  }

  if (opts.raw && (res.ok || res.status === 304)) {
    return { status: res.status, data, etag: res.headers.get('ETag') || '' };
  }
  if (!res.ok) {
    if (res.status === 401 && !opts.quiet401 && unauthorizedHandler) unauthorizedHandler();
    const message = (data && data.error) || res.statusText || 'Request failed (' + res.status + ')';
    throw new ApiError(res.status, message, data);
  }
  return data;
}

export const api = {
  get: (path, opts) => request('GET', path, opts),
  post: (path, body, opts) => request('POST', path, Object.assign({ body: body === undefined ? {} : body }, opts)),
  put: (path, body, opts) => request('PUT', path, Object.assign({ body }, opts)),
  patch: (path, body, opts) => request('PATCH', path, Object.assign({ body }, opts)),
  del: (path, opts) => request('DELETE', path, opts),
};

/** Encodes one path segment (book ids, codes) for use in a relative URL. */
export const seg = (s) => encodeURIComponent(String(s));
