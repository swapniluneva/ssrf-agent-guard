# ssrf-agent-guard

#### SSRF-Guard is a Node.js module for protecting your HTTP/HTTPS requests against SSRF (Server-Side Request Forgery) attacks. It wraps http.Agent and https.Agent to enforce pre and post DNS host/IP checks, block access to cloud metadata endpoints, private IPs, and unsafe domains.
---

## Features

* Block requests to internal/private IPs
* Detect and block cloud provider metadata endpoints (AWS, GCP, Azure)
* DNS rebinding detection
* Fully written in TypeScript with type definitions

---

## Installation

```bash
npm install ssrf-agent-guard
# or using yarn
yarn add ssrf-agent-guard
```

---

## Usage

`isValidDomainOptions` reference [is-valid-domain](https://github.com/miguelmota/is-valid-domain)

### axios

```ts
const ssrfAgentGuard = require('ssrf-agent-guard');
const url = 'https://127.0.0.1'
const isValidDomainOptions = {
  subdomain: true,
  wildcard: true
};
axios.get(url, {httpAgent: ssrfAgentGuard(url), httpsAgent: ssrfAgentGuard(url)})
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
const isValidDomainOptions = {
  subdomain: true,
  wildcard: true
};
fetch(url, {
    agent: ssrfAgentGuard(url, isValidDomainOptions)
  })
  .then((response) => {
    console.log(`Success`);
  })
  .catch(error => {
    console.log(`${error.toString().split('\n')[0]}`);
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

## License

MIT © [Swapnil Srivastava](https://swapniluneva.github.io)
