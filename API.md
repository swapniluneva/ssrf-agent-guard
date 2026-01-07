# API Reference

Complete API documentation for `ssrf-agent-guard`.

## Table of Contents

- [Quick Start](#quick-start)
- [Main Function](#main-function)
  - [ssrfAgentGuard](#ssrfagentguard)
- [Configuration](#configuration)
  - [Options](#options)
  - [PolicyOptions](#policyoptions)
- [Types](#types)
  - [BlockReason](#blockreason)
  - [BlockEvent](#blockevent)
  - [ValidationResult](#validationresult)
- [Utility Functions](#utility-functions)
  - [validateHost](#validatehost)
  - [isCloudMetadata](#iscloudmetadata)
  - [validatePolicy](#validatepolicy)
  - [matchesDomain](#matchesdomain)
  - [getTLD](#gettld)
- [Constants](#constants)
  - [CLOUD_METADATA_HOSTS](#cloud_metadata_hosts)
- [Advanced Usage](#advanced-usage)
  - [Operation Modes](#operation-modes)
  - [Custom Policies](#custom-policies)
  - [Custom Logging](#custom-logging)
  - [Integration Examples](#integration-examples)

---

## Quick Start

```typescript
import ssrfAgentGuard from 'ssrf-agent-guard';
import axios from 'axios';

const url = 'https://api.example.com/data';

// Basic usage - blocks private IPs, cloud metadata, and DNS rebinding attacks
const response = await axios.get(url, {
  httpsAgent: ssrfAgentGuard(url)
});
```

---

## Main Function

### ssrfAgentGuard

Creates a patched HTTP/HTTPS Agent with SSRF protection.

```typescript
function ssrfAgentGuard(url: string, options?: Options): HttpAgent | HttpsAgent
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | `string` | Yes | The URL or protocol hint (e.g., `'https://...'` or `'https'`) used to determine agent type |
| `options` | `Options` | No | Configuration options for SSRF protection |

#### Returns

Returns an `http.Agent` or `https.Agent` instance with patched `createConnection` method that performs SSRF validation.

#### Example

```typescript
import ssrfAgentGuard from 'ssrf-agent-guard';

// HTTPS agent
const httpsAgent = ssrfAgentGuard('https://example.com');

// HTTP agent
const httpAgent = ssrfAgentGuard('http://example.com');

// With options
const agent = ssrfAgentGuard('https://example.com', {
  mode: 'block',
  blockCloudMetadata: true,
  detectDnsRebinding: true,
  policy: {
    denyDomains: ['evil.com'],
    denyTLD: ['local', 'internal']
  }
});
```

#### Behavior

1. **Pre-DNS Validation**: Before DNS resolution, validates the hostname against:
   - Cloud metadata endpoints
   - Policy rules (allow/deny lists)
   - Private IP addresses
   - Invalid domain syntax

2. **Post-DNS Validation**: After DNS resolution, validates resolved IPs to detect:
   - DNS rebinding attacks (legitimate domain resolving to private IP)
   - Cloud metadata IPs

3. **Error Handling**: When a request is blocked (in `'block'` mode), throws an `Error` with a descriptive message.

---

## Configuration

### Options

Main configuration interface for SSRF protection.

```typescript
interface Options {
  protocol?: string;
  metadataHosts?: string[];
  mode?: 'block' | 'report' | 'allow';
  policy?: PolicyOptions;
  blockCloudMetadata?: boolean;
  detectDnsRebinding?: boolean;
  logger?: (level: 'info' | 'warn' | 'error', msg: string, meta?: BlockEvent) => void;
}
```

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `protocol` | `string` | Inferred from URL | Protocol hint (`'http'` or `'https'`). Usually inferred automatically from the URL parameter. |
| `metadataHosts` | `string[]` | `[]` | Additional cloud metadata hosts to block. These are merged with the built-in `CLOUD_METADATA_HOSTS`. |
| `mode` | `'block' \| 'report' \| 'allow'` | `'block'` | Operation mode. See [Operation Modes](#operation-modes). |
| `policy` | `PolicyOptions` | `undefined` | Domain/TLD filtering rules. See [PolicyOptions](#policyoptions). |
| `blockCloudMetadata` | `boolean` | `true` | Whether to block requests to cloud metadata endpoints. |
| `detectDnsRebinding` | `boolean` | `true` | Whether to validate resolved IPs after DNS lookup to detect rebinding attacks. |
| `logger` | `function` | `undefined` | Callback function for logging blocked requests and warnings. |

#### Example

```typescript
const options: Options = {
  mode: 'block',
  blockCloudMetadata: true,
  detectDnsRebinding: true,
  metadataHosts: ['custom-metadata.internal'],
  policy: {
    allowDomains: ['trusted-api.com', '*.mycompany.com'],
    denyTLD: ['local']
  },
  logger: (level, msg, meta) => {
    console.log(`[${level.toUpperCase()}] ${msg}`, meta);
  }
};
```

---

### PolicyOptions

Domain-based filtering rules for fine-grained access control.

```typescript
interface PolicyOptions {
  allowDomains?: string[];
  denyDomains?: string[];
  denyTLD?: string[];
}
```

#### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `allowDomains` | `string[]` | `undefined` | Explicit allowlist of domains. When specified, **only** these domains are allowed (acts as a strict allowlist). Supports wildcards. |
| `denyDomains` | `string[]` | `undefined` | Domains to explicitly deny. Supports wildcards. |
| `denyTLD` | `string[]` | `undefined` | Top-level domains to deny (e.g., `['local', 'internal', 'test']`). |

#### Domain Pattern Matching

All domain lists support these matching patterns:

- **Exact match**: `'example.com'` matches only `example.com`
- **Subdomain match**: `'example.com'` also matches `sub.example.com`, `a.b.example.com`
- **Wildcard match**: `'*.example.com'` matches `sub.example.com` but also `example.com`

#### Evaluation Order

1. If `allowDomains` is specified and non-empty:
   - If hostname matches any allowed domain → **Allow**
   - Otherwise → **Block** (reason: `'not_allowed_domain'`)
2. If hostname matches any `denyDomains` → **Block** (reason: `'denied_domain'`)
3. If hostname's TLD is in `denyTLD` → **Block** (reason: `'denied_tld'`)
4. Otherwise → **Allow** (continue to other checks)

#### Examples

```typescript
// Strict allowlist - only allow specific domains
const strictPolicy: PolicyOptions = {
  allowDomains: ['api.mycompany.com', '*.trusted-partner.com']
};

// Denylist approach - block specific domains/TLDs
const denyPolicy: PolicyOptions = {
  denyDomains: ['evil.com', '*.malicious.net'],
  denyTLD: ['local', 'internal', 'localhost', 'test']
};

// Combined (allowDomains takes precedence)
const combinedPolicy: PolicyOptions = {
  allowDomains: ['api.mycompany.com'],
  denyDomains: ['evil.com'], // This is ignored when allowDomains is set
  denyTLD: ['local'] // This is also ignored when allowDomains is set
};
```

---

## Types

### BlockReason

Union type representing the reason a request was blocked.

```typescript
type BlockReason =
  | 'private_ip'
  | 'cloud_metadata'
  | 'invalid_domain'
  | 'dns_rebinding'
  | 'denied_domain'
  | 'denied_tld'
  | 'not_allowed_domain';
```

#### Values

| Value | Description |
|-------|-------------|
| `'private_ip'` | Request targets a private/internal IP address (loopback, link-local, private ranges) |
| `'cloud_metadata'` | Request targets a cloud provider metadata endpoint |
| `'invalid_domain'` | Domain name has invalid syntax |
| `'dns_rebinding'` | DNS rebinding attack detected (domain resolved to unsafe IP) |
| `'denied_domain'` | Domain is in the `denyDomains` policy list |
| `'denied_tld'` | Domain's TLD is in the `denyTLD` policy list |
| `'not_allowed_domain'` | Domain is not in the `allowDomains` policy list (when allowlist is active) |

---

### BlockEvent

Event data passed to the logger callback when a request is blocked or flagged.

```typescript
interface BlockEvent {
  url: string;
  reason: BlockReason;
  ip?: string;
  hostname?: string;
  timestamp: number;
}
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `url` | `string` | The original URL or hostname that was blocked |
| `reason` | `BlockReason` | The reason for blocking |
| `ip` | `string \| undefined` | The resolved IP address (available for DNS rebinding detections) |
| `hostname` | `string \| undefined` | The original hostname before DNS resolution |
| `timestamp` | `number` | Unix timestamp (milliseconds) when the event occurred |

#### Example

```typescript
const logger = (level: string, msg: string, meta?: BlockEvent) => {
  if (meta) {
    console.log({
      level,
      message: msg,
      url: meta.url,
      reason: meta.reason,
      ip: meta.ip,
      hostname: meta.hostname,
      timestamp: new Date(meta.timestamp).toISOString()
    });
  }
};
```

---

### ValidationResult

Result returned by validation functions.

```typescript
interface ValidationResult {
  safe: boolean;
  reason?: BlockReason;
}
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `safe` | `boolean` | `true` if the host passed validation, `false` if blocked |
| `reason` | `BlockReason \| undefined` | The reason for blocking (only present when `safe` is `false`) |

#### Example

```typescript
import { validateHost, ValidationResult } from 'ssrf-agent-guard';

const result: ValidationResult = validateHost('192.168.1.1');
if (!result.safe) {
  console.log(`Blocked: ${result.reason}`); // "Blocked: private_ip"
}
```

---

## Utility Functions

These functions are exported for advanced use cases where you need to perform validation outside of the HTTP agent context.

### validateHost

High-level validation for hostnames and IP addresses.

```typescript
function validateHost(hostname: string, options?: Options): ValidationResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | `string` | Yes | The hostname or IP address to validate |
| `options` | `Options` | No | Configuration options |

#### Returns

`ValidationResult` with `safe` status and optional `reason`.

#### Validation Order

1. Check if hostname is a cloud metadata endpoint
2. For non-IP hostnames, check policy rules (allow/deny)
3. For IP addresses, check if public
4. For domain names, validate syntax

#### Example

```typescript
import { validateHost } from 'ssrf-agent-guard';

// Validate an IP
validateHost('127.0.0.1');
// { safe: false, reason: 'private_ip' }

// Validate a domain
validateHost('google.com');
// { safe: true }

// Validate with policy
validateHost('evil.com', {
  policy: { denyDomains: ['evil.com'] }
});
// { safe: false, reason: 'denied_domain' }

// Validate cloud metadata
validateHost('169.254.169.254');
// { safe: false, reason: 'cloud_metadata' }
```

---

### isCloudMetadata

Checks if a hostname is a cloud metadata endpoint.

```typescript
function isCloudMetadata(hostname: string, customHosts?: string[]): boolean
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | `string` | Yes | The hostname to check |
| `customHosts` | `string[]` | No | Additional custom metadata hosts to check |

#### Returns

`true` if the hostname is a cloud metadata endpoint, `false` otherwise.

#### Example

```typescript
import { isCloudMetadata } from 'ssrf-agent-guard';

isCloudMetadata('169.254.169.254');        // true (AWS/Azure/GCP)
isCloudMetadata('metadata.google.internal'); // true (GCP)
isCloudMetadata('168.63.129.16');           // true (Azure)
isCloudMetadata('example.com');              // false

// With custom hosts
isCloudMetadata('custom-metadata.local', ['custom-metadata.local']); // true
```

---

### validatePolicy

Validates a hostname against policy options.

```typescript
function validatePolicy(hostname: string, policy?: PolicyOptions): ValidationResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | `string` | Yes | The hostname to validate |
| `policy` | `PolicyOptions` | No | Policy options |

#### Returns

`ValidationResult` with `safe` status and optional `reason`.

#### Example

```typescript
import { validatePolicy } from 'ssrf-agent-guard';

// No policy - always safe
validatePolicy('anything.com');
// { safe: true }

// Allowlist mode
validatePolicy('allowed.com', {
  allowDomains: ['allowed.com']
});
// { safe: true }

validatePolicy('other.com', {
  allowDomains: ['allowed.com']
});
// { safe: false, reason: 'not_allowed_domain' }

// Denylist mode
validatePolicy('evil.com', {
  denyDomains: ['evil.com']
});
// { safe: false, reason: 'denied_domain' }

// TLD filtering
validatePolicy('service.local', {
  denyTLD: ['local']
});
// { safe: false, reason: 'denied_tld' }
```

---

### matchesDomain

Checks if a hostname matches a domain pattern.

```typescript
function matchesDomain(hostname: string, pattern: string): boolean
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | `string` | Yes | The hostname to check |
| `pattern` | `string` | Yes | The domain pattern to match against |

#### Returns

`true` if the hostname matches the pattern, `false` otherwise.

#### Pattern Types

- **Exact match**: `example.com` matches `example.com`
- **Subdomain match**: `example.com` matches `sub.example.com`
- **Wildcard match**: `*.example.com` matches `sub.example.com` and `example.com`

#### Example

```typescript
import { matchesDomain } from 'ssrf-agent-guard';

// Exact match
matchesDomain('example.com', 'example.com');     // true
matchesDomain('other.com', 'example.com');       // false

// Subdomain match (pattern without wildcard)
matchesDomain('sub.example.com', 'example.com'); // true
matchesDomain('a.b.example.com', 'example.com'); // true

// Wildcard match
matchesDomain('sub.example.com', '*.example.com'); // true
matchesDomain('example.com', '*.example.com');     // true
matchesDomain('other.com', '*.example.com');       // false

// Case insensitive
matchesDomain('SUB.EXAMPLE.COM', 'example.com'); // true
```

---

### getTLD

Extracts the top-level domain from a hostname.

```typescript
function getTLD(hostname: string): string
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | `string` | Yes | The hostname to extract TLD from |

#### Returns

The TLD (lowercase) or empty string if not found.

#### Example

```typescript
import { getTLD } from 'ssrf-agent-guard';

getTLD('example.com');       // 'com'
getTLD('sub.example.co.uk'); // 'uk'
getTLD('localhost');         // 'localhost'
getTLD('service.local');     // 'local'
getTLD('');                  // ''
```

---

## Constants

### CLOUD_METADATA_HOSTS

A `Set<string>` containing the default cloud metadata endpoints that are blocked.

```typescript
const CLOUD_METADATA_HOSTS: Set<string>
```

#### Included Endpoints

| Provider | Endpoints |
|----------|-----------|
| **AWS EC2** | `169.254.169.254`, `169.254.169.253` |
| **AWS Fargate/ECS** | `169.254.170.2` |
| **GCP** | `metadata.google.internal`, `metadata.goog` |
| **Azure IMDS** | `169.254.169.254`, `168.63.129.16` |
| **Kubernetes** | `kubernetes.default`, `kubernetes.default.svc`, `kubernetes.default.svc.cluster.local` |
| **Oracle Cloud** | `169.254.169.254` |
| **DigitalOcean** | `169.254.169.254` |
| **Alibaba Cloud** | `100.100.100.200` |
| **Link-local** | `169.254.0.0` |

#### Example

```typescript
import { CLOUD_METADATA_HOSTS } from 'ssrf-agent-guard';

// Check if a host is in the default list
CLOUD_METADATA_HOSTS.has('169.254.169.254'); // true
CLOUD_METADATA_HOSTS.has('example.com');      // false

// Iterate over all metadata hosts
for (const host of CLOUD_METADATA_HOSTS) {
  console.log(host);
}
```

---

## Advanced Usage

### Operation Modes

The library supports three operation modes via the `mode` option:

#### Block Mode (Default)

Throws an error when an SSRF attempt is detected, preventing the request.

```typescript
const agent = ssrfAgentGuard(url, { mode: 'block' });

try {
  await axios.get('http://169.254.169.254/latest/meta-data/', {
    httpAgent: agent
  });
} catch (error) {
  console.error(error.message);
  // "Cloud metadata endpoint 169.254.169.254 is not allowed"
}
```

#### Report Mode

Logs warnings but allows the request to proceed. Useful for monitoring and gradual rollout.

```typescript
const agent = ssrfAgentGuard(url, {
  mode: 'report',
  logger: (level, msg, meta) => {
    // Send to monitoring system
    metrics.increment('ssrf.detected', { reason: meta?.reason });
    console.warn(`[SSRF Report] ${msg}`, meta);
  }
});

// Request proceeds but is logged
await axios.get('http://169.254.169.254/', { httpAgent: agent });
```

#### Allow Mode

Disables all SSRF checks. Use only for debugging or testing.

```typescript
const agent = ssrfAgentGuard(url, { mode: 'allow' });
// No validation performed
```

---

### Custom Policies

#### Strict Allowlist

Only allow requests to specific trusted domains:

```typescript
const agent = ssrfAgentGuard(url, {
  policy: {
    allowDomains: [
      'api.mycompany.com',
      '*.trusted-partner.com',
      'cdn.provider.com'
    ]
  }
});
```

#### Block Internal TLDs

Block requests to internal/development TLDs:

```typescript
const agent = ssrfAgentGuard(url, {
  policy: {
    denyTLD: ['local', 'internal', 'localhost', 'test', 'example', 'invalid']
  }
});
```

#### Block Specific Domains

Block known malicious or unwanted domains:

```typescript
const agent = ssrfAgentGuard(url, {
  policy: {
    denyDomains: [
      'evil.com',
      '*.malicious.net',
      'competitor-api.com'
    ]
  }
});
```

#### Custom Metadata Hosts

Add organization-specific metadata endpoints:

```typescript
const agent = ssrfAgentGuard(url, {
  metadataHosts: [
    'metadata.internal.mycompany.com',
    'config-service.local'
  ]
});
```

---

### Custom Logging

#### Basic Console Logging

```typescript
const agent = ssrfAgentGuard(url, {
  logger: (level, msg, meta) => {
    console.log(`[${level.toUpperCase()}] ${msg}`);
    if (meta) {
      console.log('  Details:', JSON.stringify(meta, null, 2));
    }
  }
});
```

#### Integration with Logging Libraries

```typescript
import winston from 'winston';

const logger = winston.createLogger({ /* config */ });

const agent = ssrfAgentGuard(url, {
  logger: (level, msg, meta) => {
    logger.log({
      level,
      message: msg,
      ...meta
    });
  }
});
```

#### Send to Monitoring Service

```typescript
const agent = ssrfAgentGuard(url, {
  mode: 'report', // Log but don't block
  logger: async (level, msg, meta) => {
    if (meta) {
      await fetch('https://monitoring.mycompany.com/ssrf-events', {
        method: 'POST',
        body: JSON.stringify({
          severity: level,
          message: msg,
          event: meta,
          service: 'my-service',
          environment: process.env.NODE_ENV
        })
      });
    }
  }
});
```

---

### Integration Examples

#### Axios

```typescript
import axios from 'axios';
import ssrfAgentGuard from 'ssrf-agent-guard';

const options = {
  policy: { denyTLD: ['local'] },
  logger: console.log
};

const url = 'https://api.example.com/data';

const response = await axios.get(url, {
  httpAgent: ssrfAgentGuard('http', options),
  httpsAgent: ssrfAgentGuard('https', options)
});
```

#### node-fetch

```typescript
import fetch from 'node-fetch';
import ssrfAgentGuard from 'ssrf-agent-guard';

const url = 'https://api.example.com/data';

const response = await fetch(url, {
  agent: ssrfAgentGuard(url)
});
```

#### Got

```typescript
import got from 'got';
import ssrfAgentGuard from 'ssrf-agent-guard';

const options = { mode: 'block' as const };

const response = await got('https://api.example.com/data', {
  agent: {
    http: ssrfAgentGuard('http', options),
    https: ssrfAgentGuard('https', options)
  }
});
```

#### Undici (fetch)

```typescript
import { fetch, Agent } from 'undici';
import ssrfAgentGuard, { validateHost } from 'ssrf-agent-guard';

// For Undici, use validateHost for pre-request validation
const url = 'https://api.example.com/data';
const parsedUrl = new URL(url);

const validation = validateHost(parsedUrl.hostname);
if (!validation.safe) {
  throw new Error(`SSRF blocked: ${validation.reason}`);
}

const response = await fetch(url);
```

#### Express Middleware

```typescript
import express from 'express';
import axios from 'axios';
import ssrfAgentGuard from 'ssrf-agent-guard';

const app = express();

app.post('/fetch-url', async (req, res) => {
  const { url } = req.body;

  try {
    const response = await axios.get(url, {
      httpAgent: ssrfAgentGuard('http'),
      httpsAgent: ssrfAgentGuard('https'),
      timeout: 5000
    });
    res.json({ data: response.data });
  } catch (error) {
    if (error.message.includes('not allowed')) {
      res.status(403).json({ error: 'URL not allowed' });
    } else {
      res.status(500).json({ error: 'Request failed' });
    }
  }
});
```

---

## Error Messages

When a request is blocked in `'block'` mode, the following error messages are thrown:

| Block Reason | Error Message |
|--------------|---------------|
| `private_ip` | `Private IP address {target} is not allowed` |
| `cloud_metadata` | `Cloud metadata endpoint {target} is not allowed` |
| `invalid_domain` | `Invalid domain {target}` |
| `dns_rebinding` | `DNS rebinding attack detected for {hostname} -> {ip}` |
| `denied_domain` | `Domain {target} is denied by policy` |
| `denied_tld` | `TLD of {target} is denied by policy` |
| `not_allowed_domain` | `Domain {target} is not in the allowed list` |

---

## TypeScript Support

This library is written in TypeScript and includes full type definitions. All types are exported from the main module:

```typescript
import ssrfAgentGuard, {
  Options,
  PolicyOptions,
  BlockEvent,
  BlockReason,
  ValidationResult,
  validateHost,
  isCloudMetadata,
  validatePolicy,
  matchesDomain,
  getTLD,
  CLOUD_METADATA_HOSTS
} from 'ssrf-agent-guard';
```
