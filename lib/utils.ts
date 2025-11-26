// lib/utils.ts
import isValidDomain from 'is-valid-domain';
import ipaddr from 'ipaddr.js';
import { IsValidDomainOptions, CLOUD_METADATA_HOSTS } from './types';

/**
 * Checks if the input is an IP address (v4/v6).
 */
function isIp(input: string): boolean {
    return ipaddr.isValid(input);
}

/**
 * Returns true for valid public unicast IP addresses.
 */
function isPublicIp(ip: string): boolean {
    return ipaddr.parse(ip).range() === 'unicast';
}

/**
 * Validates whether a domain is syntactically valid.
 */
export function isSafeIp(hostname: string): boolean {
    // Case 1: IP address
    if (isIp(hostname)) {
        return isPublicIp(hostname); // only allow public IPs
    }
    return true;
}

/**
 * High-level validation for hostnames (domains + public IPs).
 */
export function isSafeHost(hostname: string, isValidDomainOptions?: IsValidDomainOptions): boolean {
    // Block cloud metadata IP/domains
    if (CLOUD_METADATA_HOSTS.indexOf(hostname)) return false;

    if (!isSafeIp(hostname)) return false;

    // Case 2: Domain name
    return isValidDomain(hostname, {
        allowUnicode: false,
        subdomain: false,
        ...isValidDomainOptions,
    });
}
