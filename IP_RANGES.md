# Blocked IP Ranges

This document provides comprehensive documentation of all IP address ranges blocked by `ssrf-agent-guard` and the security reasoning behind each.

## Table of Contents

- [Overview](#overview)
- [How IP Validation Works](#how-ip-validation-works)
- [Blocked IPv4 Ranges](#blocked-ipv4-ranges)
- [Blocked IPv6 Ranges](#blocked-ipv6-ranges)
- [Cloud Metadata Endpoints](#cloud-metadata-endpoints)
- [Security Rationale](#security-rationale)
- [Configuration](#configuration)

---

## Overview

`ssrf-agent-guard` blocks access to non-public IP addresses to prevent Server-Side Request Forgery (SSRF) attacks. SSRF vulnerabilities allow attackers to make requests from your server to internal resources, potentially exposing sensitive data, internal services, or cloud credentials.

The library uses a **unicast-only** approach: only publicly routable unicast IP addresses are allowed. All other IP classifications (private, reserved, loopback, link-local, multicast, broadcast) are blocked by default.

---

## How IP Validation Works

IP validation is performed using the [`ipaddr.js`](https://www.npmjs.com/package/ipaddr.js) library. An IP address is considered **safe** only if:

```typescript
ipaddr.parse(ip).range() === 'unicast'
```

Any IP that returns a range other than `'unicast'` is blocked. This includes:

| Range Classification | Blocked? |
|---------------------|----------|
| `unicast` | No (allowed) |
| `private` | Yes |
| `loopback` | Yes |
| `linkLocal` | Yes |
| `multicast` | Yes |
| `broadcast` | Yes |
| `unspecified` | Yes |
| `reserved` | Yes |
| `carrierGradeNat` | Yes |

---

## Blocked IPv4 Ranges

### Loopback Addresses

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `127.0.0.0/8` | 127.0.0.1 - 127.255.255.255 | Localhost/loopback | Prevents access to services running on the same machine (databases, admin panels, internal APIs) |

**Examples:** `127.0.0.1`, `127.0.0.2`, `127.1.1.1`

### Private Networks (RFC 1918)

These ranges are reserved for private networks and are not routable on the public internet.

| CIDR | Range | Class | Why Blocked |
|------|-------|-------|-------------|
| `10.0.0.0/8` | 10.0.0.0 - 10.255.255.255 | Class A Private | Internal corporate networks, cloud VPCs, internal services |
| `172.16.0.0/12` | 172.16.0.0 - 172.31.255.255 | Class B Private | Docker default networks, internal services |
| `192.168.0.0/16` | 192.168.0.0 - 192.168.255.255 | Class C Private | Home/office LANs, development environments |

**Examples:** `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `192.168.0.100`

### Link-Local Addresses

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `169.254.0.0/16` | 169.254.0.0 - 169.254.255.255 | Link-local (APIPA) | Cloud metadata services, auto-configured addresses |

**Critical:** This range includes cloud metadata endpoints:
- `169.254.169.254` - AWS, Azure, GCP, Oracle Cloud, DigitalOcean
- `169.254.169.253` - AWS secondary
- `169.254.170.2` - AWS ECS/Fargate task metadata

### Carrier-Grade NAT (CGN)

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `100.64.0.0/10` | 100.64.0.0 - 100.127.255.255 | Shared Address Space (RFC 6598) | ISP internal networks, potential for internal service access |

### Special Purpose Addresses

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `0.0.0.0/8` | 0.0.0.0 - 0.255.255.255 | "This" network | Non-routable, can represent localhost in some contexts |
| `255.255.255.255/32` | 255.255.255.255 | Broadcast | Network broadcast address |
| `224.0.0.0/4` | 224.0.0.0 - 239.255.255.255 | Multicast | Multicast traffic, not for unicast requests |
| `240.0.0.0/4` | 240.0.0.0 - 255.255.255.254 | Reserved | Reserved for future use |

### Documentation & Testing (RFC 5737)

| CIDR | Purpose | Why Blocked |
|------|---------|-------------|
| `192.0.2.0/24` | TEST-NET-1 (documentation) | Not routable |
| `198.51.100.0/24` | TEST-NET-2 (documentation) | Not routable |
| `203.0.113.0/24` | TEST-NET-3 (documentation) | Not routable |

### Benchmarking (RFC 2544)

| CIDR | Purpose | Why Blocked |
|------|---------|-------------|
| `198.18.0.0/15` | Benchmark testing | Reserved for network device benchmarking |

---

## Blocked IPv6 Ranges

### Loopback

| CIDR | Address | Purpose | Why Blocked |
|------|---------|---------|-------------|
| `::1/128` | ::1 | IPv6 loopback | Same as IPv4 127.0.0.1 - prevents localhost access |

### Unspecified

| CIDR | Address | Purpose | Why Blocked |
|------|---------|---------|-------------|
| `::/128` | :: | Unspecified address | Invalid destination address |

### Unique Local Addresses (ULA)

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `fc00::/7` | fc00:: - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff | Private networks | IPv6 equivalent of RFC 1918 private addresses |

This includes:
- `fc00::/8` - Centrally assigned (not yet allocated)
- `fd00::/8` - Locally assigned (commonly used)

**Examples:** `fd00::1`, `fd12:3456:789a::1`

### Link-Local

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `fe80::/10` | fe80:: - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff | Link-local | Auto-configured, interface-specific addresses |

### Multicast

| CIDR | Range | Purpose | Why Blocked |
|------|-------|---------|-------------|
| `ff00::/8` | ff00:: - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff | Multicast | Group communication, not unicast |

### IPv4-Mapped IPv6

| CIDR | Format | Purpose | Why Blocked |
|------|--------|---------|-------------|
| `::ffff:0:0/96` | `::ffff:a.b.c.d` | IPv4-mapped | The embedded IPv4 address is validated separately |

**Example:** `::ffff:127.0.0.1` (maps to 127.0.0.1, blocked as loopback)

### Deprecated/Reserved

| CIDR | Purpose | Why Blocked |
|------|---------|-------------|
| `::ffff:0:0:0/96` | IPv4-translated | Deprecated |
| `64:ff9b::/96` | NAT64 well-known prefix | Translation prefix |
| `100::/64` | Discard prefix | Packets should be discarded |
| `2001:db8::/32` | Documentation | Reserved for documentation examples |

---

## Cloud Metadata Endpoints

Cloud metadata services expose sensitive information including:
- IAM credentials and access tokens
- SSH keys
- Instance identity documents
- Network configuration
- User data scripts (may contain secrets)

### Blocked by IP Address

| IP Address | Cloud Provider(s) | Service |
|------------|-------------------|---------|
| `169.254.169.254` | AWS, Azure, GCP, Oracle Cloud, DigitalOcean | Instance Metadata Service (IMDS) |
| `169.254.169.253` | AWS | Secondary metadata endpoint |
| `169.254.170.2` | AWS | ECS/Fargate task metadata |
| `168.63.129.16` | Azure | Wireserver (health probes, DNS, IMDS) |
| `100.100.100.200` | Alibaba Cloud | Metadata service |

### Blocked by Hostname

| Hostname | Cloud Provider | Service |
|----------|----------------|---------|
| `metadata.google.internal` | GCP | Compute Engine metadata |
| `metadata.goog` | GCP | Alternative metadata hostname |
| `kubernetes.default` | Kubernetes | API server |
| `kubernetes.default.svc` | Kubernetes | API server (FQDN) |
| `kubernetes.default.svc.cluster.local` | Kubernetes | API server (full FQDN) |

### Dangerous Metadata Paths

If an attacker reaches these endpoints, they can access:

```
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/identity/oauth2/token

# Kubernetes
https://kubernetes.default.svc/api/v1/namespaces/default/secrets/
```

---

## Security Rationale

### Why Block Private IPs?

1. **Internal Service Access**: Attackers can probe and access internal services (databases, caches, admin panels) that are not exposed to the internet.

2. **Cloud Infrastructure Exploitation**: Access to VPC/VNet resources, internal load balancers, and private APIs.

3. **Lateral Movement**: Using SSRF as a pivot point to reach other systems in the network.

4. **Data Exfiltration**: Reading responses from internal services and exfiltrating sensitive data.

### Why Block Metadata Endpoints?

1. **Credential Theft**: Cloud metadata services provide temporary credentials that can be used to access cloud resources (S3, databases, etc.).

2. **Identity Assumption**: Stolen credentials allow attackers to impersonate the service's IAM role.

3. **Information Disclosure**: Metadata reveals network topology, instance details, and potentially secrets in user-data.

### Why DNS Rebinding Protection?

DNS rebinding is a technique where:
1. Attacker controls `evil.com` which initially resolves to a public IP
2. Pre-DNS validation passes (domain looks legitimate)
3. DNS TTL expires or attacker changes record
4. `evil.com` now resolves to `127.0.0.1` or `169.254.169.254`
5. Request reaches internal/metadata service

`ssrf-agent-guard` prevents this by validating the resolved IP **after** DNS resolution in addition to pre-DNS validation.

---

## Configuration

### Allowing Specific Private IPs

If you need to allow specific internal services, use domain-based allowlists instead of disabling IP checks:

```typescript
const agent = ssrfAgentGuard(url, {
  policy: {
    allowDomains: ['internal-api.mycompany.com']
  }
});
```

### Adding Custom Metadata Hosts

Block additional metadata endpoints specific to your environment:

```typescript
const agent = ssrfAgentGuard(url, {
  metadataHosts: [
    'custom-metadata.internal',
    'config-service.local'
  ]
});
```

### Report Mode for Monitoring

Before enabling blocking, use report mode to understand traffic patterns:

```typescript
const agent = ssrfAgentGuard(url, {
  mode: 'report',
  logger: (level, msg, meta) => {
    console.log(`[${level}] ${msg}`, meta);
  }
});
```

---

## References

- [RFC 1918 - Private Address Space](https://tools.ietf.org/html/rfc1918)
- [RFC 5737 - IPv4 Address Blocks for Documentation](https://tools.ietf.org/html/rfc5737)
- [RFC 6598 - Shared Address Space](https://tools.ietf.org/html/rfc6598)
- [RFC 4193 - Unique Local IPv6 Unicast Addresses](https://tools.ietf.org/html/rfc4193)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- [Azure IMDS Documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [GCP Metadata Server](https://cloud.google.com/compute/docs/metadata/overview)
