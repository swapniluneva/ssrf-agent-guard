# Framework Examples

This directory contains examples demonstrating how to integrate `ssrf-agent-guard` with popular Node.js frameworks.

## Available Examples

| Framework | Description | Directory |
|-----------|-------------|-----------|
| [Express.js](./express) | Middleware and route handlers with axios | `examples/express` |
| [Fastify](./fastify) | Plugin-based integration with undici | `examples/fastify` |
| [NestJS](./nestjs) | Module and service-based integration | `examples/nestjs` |

## Quick Start

Each example is a standalone project. To run an example:

```bash
cd examples/<framework>
npm install
npm start
```

Then test with curl:

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

## Common Patterns

### Basic Protected Fetch

```javascript
const ssrfAgentGuard = require('ssrf-agent-guard');
const axios = require('axios');

async function protectedFetch(url) {
  const agent = ssrfAgentGuard(url, {
    mode: 'block',
    blockCloudMetadata: true,
    detectDnsRebinding: true,
  });

  return axios.get(url, {
    httpAgent: agent,
    httpsAgent: agent,
  });
}
```

### Domain Allowlist

```javascript
const agent = ssrfAgentGuard(url, {
  policy: {
    allowDomains: ['api.github.com', '*.trusted.com'],
  },
});
```

### Error Handling

```javascript
try {
  await protectedFetch(userProvidedUrl);
} catch (error) {
  if (error.message.includes('SSRF')) {
    // Request was blocked by SSRF protection
    return res.status(403).json({ error: 'URL not allowed' });
  }
  throw error;
}
```

### Custom Logging

```javascript
const agent = ssrfAgentGuard(url, {
  logger: (level, message, meta) => {
    console.log(`[SSRF-Guard][${level}] ${message}`, meta);
  },
});
```

## What Each Example Demonstrates

- **Basic SSRF protection** - Blocking private IPs and cloud metadata
- **Policy configuration** - Allowlists, denylists, and TLD blocking
- **Error handling** - Proper responses for blocked requests
- **Webhook verification** - Validating user-provided callback URLs
- **Image proxy** - Strict allowlist for proxying external content
- **URL validation** - Checking URLs without making requests
