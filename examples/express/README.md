# Express.js SSRF Protection Example

This example demonstrates how to use `ssrf-agent-guard` with Express.js to protect your application from SSRF attacks.

## Setup

```bash
cd examples/express
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

# SSRF attempt - blocked (cloud metadata)
curl -X POST http://localhost:3000/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# SSRF attempt - blocked (private IP)
curl -X POST http://localhost:3000/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.1.1/"}'
```

### POST /api/webhooks/verify
Verifies a webhook URL is safe and reachable.

```bash
curl -X POST http://localhost:3000/api/webhooks/verify \
  -H "Content-Type: application/json" \
  -d '{"webhookUrl":"https://webhook.site/your-id"}'
```

### GET /api/proxy/image
Proxies images from allowed CDN domains only.

```bash
curl "http://localhost:3000/api/proxy/image?src=https://images.unsplash.com/photo-example"
```

## Key Patterns

### Protected HTTP Client

```javascript
const ssrfAgentGuard = require('ssrf-agent-guard');
const axios = require('axios');

async function protectedFetch(url, options = {}) {
  const agent = ssrfAgentGuard(url, {
    mode: 'block',
    blockCloudMetadata: true,
    detectDnsRebinding: true
  });

  return axios({
    url,
    httpAgent: agent,
    httpsAgent: agent,
    ...options
  });
}
```

### Domain Allowlist

```javascript
const agent = ssrfAgentGuard(url, {
  policy: {
    allowDomains: ['*.trusted-api.com', 'api.example.com']
  }
});
```

### Error Handling

```javascript
function isSsrfError(error) {
  const msg = error.message || '';
  return msg.includes('is not allowed') ||
         msg.includes('is denied') ||
         msg.includes('rebinding');
}

try {
  await protectedFetch(userProvidedUrl);
} catch (error) {
  if (isSsrfError(error)) {
    // Request was blocked - handle appropriately
    return res.status(403).json({ error: 'URL not allowed' });
  }
  throw error;
}
```
