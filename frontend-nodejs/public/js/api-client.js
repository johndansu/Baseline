export class DashboardAPIError extends Error {
    constructor(message, details = {}) {
        super(message);
        this.name = 'DashboardAPIError';
        this.code = details.code || '';
        this.status = details.status || 0;
        this.requestID = details.requestID || '';
    }
}

export class DashboardAPIClient {
    constructor(options = {}) {
        this.baseURL = String(options.baseURL || window.location.origin).replace(/\/+$/, '');
        this.onUnauthorized = typeof options.onUnauthorized === 'function'
            ? options.onUnauthorized
            : () => {};
    }

    buildURL(path) {
        const normalized = String(path || '').trim();
        if (!normalized.startsWith('/')) {
            throw new DashboardAPIError('API path must start with "/"', { code: 'client_invalid_path' });
        }
        return `${this.baseURL}${normalized}`;
    }

    async requestJSON(path, options = {}) {
        const response = await this.request(path, {
            ...options,
            headers: {
                'Accept': 'application/json',
                ...(options.headers || {})
            }
        });
        const text = await response.text();
        if (!text) {
            return {};
        }
        try {
            return JSON.parse(text);
        } catch (_) {
            throw new DashboardAPIError('Invalid JSON response from API', {
                code: 'invalid_json_response',
                status: response.status
            });
        }
    }

    async requestBlob(path, options = {}) {
        const response = await this.request(path, options);
        const blob = await response.blob();
        return { blob, response };
    }

    async request(path, options = {}) {
        const method = String(options.method || 'GET').toUpperCase();
        const headers = this.normalizeHeaders(options.headers);
        const suppressUnauthorizedHandler = options.suppressUnauthorizedHandler === true;
        if (this.isMutatingMethod(method) && !this.hasHeader(headers, 'X-Baseline-CSRF')) {
            headers['X-Baseline-CSRF'] = '1';
        }

        const response = await fetch(this.buildURL(path), {
            method: method,
            credentials: 'include',
            headers: headers,
            body: options.body
        });

        if (response.status === 401) {
            if (!suppressUnauthorizedHandler) {
                this.onUnauthorized();
            }
            throw new DashboardAPIError('Unauthorized', { code: 'unauthorized', status: 401 });
        }

        if (response.ok) {
            return response;
        }

        const bodyText = await response.text();
        let errorCode = '';
        let errorMessage = `Request failed with status ${response.status}`;
        let requestID = response.headers.get('X-Request-ID') || '';

        if (bodyText) {
            try {
                const payload = JSON.parse(bodyText);
                if (payload && payload.error) {
                    if (payload.error.code) errorCode = String(payload.error.code);
                    if (payload.error.message) errorMessage = String(payload.error.message);
                    if (payload.error.request_id) requestID = String(payload.error.request_id);
                }
            } catch (_) {
                // Keep generic error values for non-JSON error payloads.
            }
        }

        throw new DashboardAPIError(errorMessage, {
            code: errorCode,
            status: response.status,
            requestID: requestID
        });
    }

    isMutatingMethod(method) {
        return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    }

    normalizeHeaders(headers) {
        if (!headers) {
            return {};
        }
        if (headers instanceof Headers) {
            return Object.fromEntries(headers.entries());
        }
        return { ...headers };
    }

    hasHeader(headers, name) {
        const target = String(name || '').toLowerCase();
        return Object.keys(headers || {}).some((key) => String(key).toLowerCase() === target);
    }
}
