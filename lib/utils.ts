// lib/utils.ts
import isValidDomain from 'is-valid-domain';
import ipaddr from 'ipaddr.js';
import { CLOUD_METADATA_HOSTS, Options, PolicyOptions, ValidationResult } from './types';

/**
 * Checks if the input is an IP address (v4/v6).
 */
export function isIp(input: string): boolean {
    return ipaddr.isValid(input);
}

/**
 * Returns true for valid public unicast IP addresses.
 */
export function isPublicIp(ip: string): boolean {
    return ipaddr.parse(ip).range() === 'unicast';
}

/**
 * Extracts the TLD from a hostname.
 * @param hostname The hostname to extract TLD from
 * @returns The TLD or empty string if not found
 */
export function getTLD(hostname: string): string {
    const parts = hostname.toLowerCase().split('.');
    return parts.length > 0 ? parts[parts.length - 1] : '';
}

/**
 * Checks if a hostname matches a domain pattern.
 * Supports exact match and wildcard subdomain matching.
 * @param hostname The hostname to check
 * @param pattern The domain pattern (e.g., 'example.com' or '*.example.com')
 */
export function matchesDomain(hostname: string, pattern: string): boolean {
    const normalizedHost = hostname.toLowerCase();
    const normalizedPattern = pattern.toLowerCase();

    // Exact match
    if (normalizedHost === normalizedPattern) {
        return true;
    }

    // Wildcard match (*.example.com matches sub.example.com)
    if (normalizedPattern.startsWith('*.')) {
        const baseDomain = normalizedPattern.slice(2);
        return normalizedHost.endsWith('.' + baseDomain) || normalizedHost === baseDomain;
    }

    // Subdomain match (example.com matches sub.example.com)
    return normalizedHost.endsWith('.' + normalizedPattern);
}

/**
 * Checks if a hostname matches any domain in a list.
 */
function matchesAnyDomain(hostname: string, domains: string[]): boolean {
    return domains.some((domain) => matchesDomain(hostname, domain));
}

/**
 * Validates a host against policy options.
 * @param hostname The hostname to validate
 * @param policy The policy options
 * @returns ValidationResult with safe status and reason if blocked
 */
export function validatePolicy(hostname: string, policy?: PolicyOptions): ValidationResult {
    if (!policy) {
        return { safe: true };
    }

    // Check allowDomains first (explicit allowlist takes precedence)
    if (policy.allowDomains && policy.allowDomains.length > 0) {
        if (matchesAnyDomain(hostname, policy.allowDomains)) {
            return { safe: true };
        }
        // If allowDomains is specified but host doesn't match, it's not allowed
        return { safe: false, reason: 'not_allowed_domain' };
    }

    // Check denyDomains
    if (policy.denyDomains && policy.denyDomains.length > 0) {
        if (matchesAnyDomain(hostname, policy.denyDomains)) {
            return { safe: false, reason: 'denied_domain' };
        }
    }

    // Check denyTLD
    if (policy.denyTLD && policy.denyTLD.length > 0) {
        const tld = getTLD(hostname);
        if (policy.denyTLD.map((t) => t.toLowerCase()).includes(tld)) {
            return { safe: false, reason: 'denied_tld' };
        }
    }

    return { safe: true };
}

/**
 * Checks if a hostname is a cloud metadata endpoint.
 * @param hostname The hostname to check
 * @param customHosts Additional custom metadata hosts to check
 */
export function isCloudMetadata(hostname: string, customHosts?: string[]): boolean {
    if (CLOUD_METADATA_HOSTS.has(hostname)) {
        return true;
    }
    if (customHosts && customHosts.includes(hostname)) {
        return true;
    }
    return false;
}

/**
 * High-level validation for hostnames (domains + public IPs).
 * Returns detailed validation result with reason for blocking.
 *
 * @param hostname The hostname or IP to validate
 * @param options Configuration options including policy and metadata settings
 * @returns ValidationResult with safe status and optional reason
 */
export function validateHost(hostname: string, options?: Options): ValidationResult {
    const blockCloudMetadata = options?.blockCloudMetadata !== false; // default true

    // Block cloud metadata IP/domains
    if (blockCloudMetadata && isCloudMetadata(hostname, options?.metadataHosts)) {
        return { safe: false, reason: 'cloud_metadata' };
    }

    // Check policy-based rules (only for non-IP hostnames)
    if (!isIp(hostname)) {
        const policyResult = validatePolicy(hostname, options?.policy);
        if (!policyResult.safe) {
            return policyResult;
        }
    }

    // Case 1: IP address
    if (isIp(hostname)) {
        if (!isPublicIp(hostname)) {
            return { safe: false, reason: 'private_ip' };
        }
        return { safe: true };
    }

    // Case 2: Domain name validation
    if (!isValidDomain(hostname, { allowUnicode: false, subdomain: true })) {
        return { safe: false, reason: 'invalid_domain' };
    }

    return { safe: true };
}
