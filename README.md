# ssrf-agent-guard

#### `ssrf-agent-guard` is a Node.js module for protecting your HTTP/HTTPS requests against SSRF (Server-Side Request Forgery) attacks. It wraps http.Agent and https.Agent to enforce pre and post DNS host/IP checks, block access to cloud metadata endpoints, private IPs, and unsafe domains.
---

## Features

* Block requests to internal/private IPs
* Detect and block cloud provider metadata endpoints (AWS, GCP, Azure, Oracle, DigitalOcean, Kubernetes)
* DNS rebinding detection
* Policy-based domain filtering (allowlists, denylists, TLD blocking)
* Multiple operation modes (block, report, allow)
* Custom logging support
* Fully written in TypeScript with type definitions

## Documentation

For complete API documentation, see [API.md](./API.md).

For framework-specific examples, see the [examples](./examples) directory:
- [Express.js](./examples/express)
- [Fastify](./examples/fastify)
- [NestJS](./examples/nestjs)

---

## Installation

```bash
npm install ssrf-agent-guard
# or using yarn
yarn add ssrf-agent-guard
```

---

## Usage

### axios

```ts
const ssrfAgentGuard = require('ssrf-agent-guard');
const url = 'https://127.0.0.1'
axios.get(
  url, {
    httpAgent: ssrfAgentGuard(url), 
    httpsAgent: ssrfAgentGuard(url)
    })
      .then((response) => {
        console.log(`Success`);
      })
      .catch((error) => {
        console.log(`${error.toString().split('\n')[0]}`);
      })
      .then(() => {

      });
```

### node-fetch

```ts
const ssrfAgentGuard = require('ssrf-agent-guard');
const url = 'https://127.0.0.1'
fetch(url, {
    agent: ssrfAgentGuard(url)
  })
  .then((response) => {
    console.log(`Success`);
  })
  .catch(error => {
    console.log(`${error.toString().split('\n')[0]}`);
  });
```

### Advanced Configuration

```ts
const ssrfAgentGuard = require('ssrf-agent-guard');

const agent = ssrfAgentGuard('https://api.example.com', {
  mode: 'block',                    // 'block' | 'report' | 'allow'
  blockCloudMetadata: true,         // Block AWS/GCP/Azure metadata endpoints
  detectDnsRebinding: true,         // Detect DNS rebinding attacks
  policy: {
    allowDomains: ['*.trusted.com'], // Only allow these domains
    denyDomains: ['evil.com'],       // Block these domains
    denyTLD: ['local', 'internal']   // Block these TLDs
  },
  logger: (level, msg, meta) => {
    console.log(`[${level}] ${msg}`, meta);
  }
});
```

---

## Development

```bash
# install dependencies
npm install

# build
npm run build

# run tests
npm test
```

---

## Contributing

1. Fork the repository
2. Create a branch (`git checkout -b feature/new-feature`)
3. Make changes and run tests
4. Commit and push your branch
5. Open a Pull Request

---

## Credits: 
  * SSRF prevention techniques: [SSRF Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
  * Implementation inspired By [ssrf-req-filter](https://github.com/y-mehta/ssrf-req-filter/)

---

## License

MIT © [Swapnil Srivastava](https://swapniluneva.github.io)
