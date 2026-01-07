# Fastify SSRF Protection Example

This example demonstrates how to use `ssrf-agent-guard` with Fastify to protect your application from SSRF attacks.

## Setup

```bash
cd examples/fastify
npm install
npm start
```

## Endpoints

### POST /api/fetch
Fetches an external URL with SSRF protection.

```bash
# Safe request - allowed
curl -X POST http://localhost:3000/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"https://httpbin.org/get"}'

# SSRF attempt - blocked
curl -X POST http://localhost:3000/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

### POST /api/validate-url
Validates a URL without making a request.

```bash
curl -X POST http://localhost:3000/api/validate-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.1.1/"}'
```

### POST /api/fetch-trusted
Fetches from allowlisted domains only.

```bash
curl -X POST http://localhost:3000/api/fetch-trusted \
  -H "Content-Type: application/json" \
  -d '{"url":"https://api.github.com/users/octocat"}'
```

## Key Patterns

### Protected Fetch Helper

```javascript
const ssrfAgentGuard = require('ssrf-agent-guard');

function isSsrfError(error) {
  const msg = error.message || '';
  return msg.includes('is not allowed') ||
         msg.includes('is denied') ||
         msg.includes('rebinding');
}

async function protectedFetch(url, options = {}) {
  const agent = ssrfAgentGuard(url, {
    mode: 'block',
    blockCloudMetadata: true,
    detectDnsRebinding: true
  });

  const fetch = (await import('node-fetch')).default;
  return fetch(url, { ...options, agent });
}
```

### URL Validation Without Request

```javascript
// Cloud metadata IPs to check
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', '169.254.169.253', '168.63.129.16'
]);

function validateUrl(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    if (CLOUD_METADATA_IPS.has(hostname)) {
      return { valid: false, reason: 'cloud_metadata' };
    }

    if (/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)/.test(hostname)) {
      return { valid: false, reason: 'private_ip' };
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: 'invalid_url' };
  }
}
```

### Strict Allowlist Policy

```javascript
const strictOptions = {
  policy: {
    allowDomains: ['api.github.com', '*.trusted.com']
  }
};

ssrfAgentGuard(url, strictOptions);
```
