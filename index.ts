import { Agent as HttpAgent, AgentOptions as HttpAgentOptions } from 'http';
import { Agent as HttpsAgent, AgentOptions as HttpsAgentOptions } from 'https';
import { Duplex } from 'stream';

import { validateHost } from './lib/utils';
import { Options, BlockEvent, BlockReason } from './lib/types';

// Re-export types for consumers
export { Options, PolicyOptions, BlockEvent, BlockReason, ValidationResult } from './lib/types';
export { validateHost, isCloudMetadata, validatePolicy, matchesDomain, getTLD } from './lib/utils';

// Define the type for the Agent that this module will modify and return.
// It can be either an HttpAgent or an HttpsAgent.
type CustomAgent = HttpAgent | HttpsAgent;

// WeakMap to track patched agents without modifying the agent object
const patchedAgents = new WeakMap<CustomAgent, boolean>();

/**
 * Determines the correct Agent instance based on the protocol.
 * @param url The URL or protocol hint to determine the agent type.
 * @param options Optional options that may contain protocol hint.
 * @returns A new HttpAgent or HttpsAgent instance.
 */
const createAgent = (url: string, options?: Options): CustomAgent => {
    const protocol = options?.protocol || url;
    if (typeof protocol === 'string' && protocol.startsWith('https')) {
        return new HttpsAgent();
    }
    return new HttpAgent();
};

/**
 * Creates a BlockEvent for logging.
 */
function createBlockEvent(
    url: string,
    reason: BlockReason,
    ip?: string,
    hostname?: string
): BlockEvent {
    return {
        url,
        reason,
        ip,
        hostname,
        timestamp: Date.now(),
    };
}

/**
 * Handles a block action based on mode.
 * @returns true if the request should be blocked, false if allowed
 */
function handleBlock(
    options: Options | undefined,
    url: string,
    reason: BlockReason,
    ip?: string,
    hostname?: string
): boolean {
    const mode = options?.mode || 'block';
    const logger = options?.logger;

    // Create event for logging
    const event = createBlockEvent(url, reason, ip, hostname);

    // Log based on mode
    if (logger) {
        if (mode === 'block') {
            logger('error', `SSRF blocked: ${reason}`, event);
        } else if (mode === 'report') {
            logger('warn', `SSRF detected (report mode): ${reason}`, event);
        }
    }

    // Return whether to actually block
    return mode === 'block';
}

/**
 * Gets a human-readable error message for a block reason.
 */
function getErrorMessage(reason: BlockReason, target: string): string {
    switch (reason) {
        case 'private_ip':
            return `Private IP address ${target} is not allowed`;
        case 'cloud_metadata':
            return `Cloud metadata endpoint ${target} is not allowed`;
        case 'invalid_domain':
            return `Invalid domain ${target}`;
        case 'dns_rebinding':
            return `DNS rebinding attack detected for ${target}`;
        case 'denied_domain':
            return `Domain ${target} is denied by policy`;
        case 'denied_tld':
            return `TLD of ${target} is denied by policy`;
        case 'not_allowed_domain':
            return `Domain ${target} is not in the allowed list`;
        default:
            return `Request to ${target} is not allowed`;
    }
}

/**
 * Patches an http.Agent or https.Agent to enforce HOST/IP checks
 * before and after DNS lookup, with full policy support.
 *
 * @param url The URL or protocol hint to determine the agent type.
 * @param options Configuration options for SSRF protection.
 * @returns The patched CustomAgent instance.
 */
function ssrfAgentGuard(url: string, options?: Options): CustomAgent {
    // Create a new agent for each call to avoid shared state issues
    const finalAgent = createAgent(url, options);

    // If mode is 'allow', return unpatched agent
    if (options?.mode === 'allow') {
        return finalAgent;
    }

    // Check if already patched (shouldn't happen with new agents, but safety check)
    if (patchedAgents.get(finalAgent)) {
        return finalAgent;
    }
    patchedAgents.set(finalAgent, true);

    // Store original createConnection
    const originalCreateConnection = finalAgent.createConnection;

    // Whether to detect DNS rebinding (default: true)
    const detectDnsRebinding = options?.detectDnsRebinding !== false;

    // Patch createConnection
    finalAgent.createConnection = function (
        connectionOptions: HttpAgentOptions | HttpsAgentOptions,
        callback?: (err: Error | null, stream: Duplex) => void,
    ) {
        const hostname = connectionOptions.host || '';

        // --- 1. Pre-DNS Check (Host/Address Check) ---
        const preCheckResult = validateHost(hostname, options);

        if (!preCheckResult.safe && preCheckResult.reason) {
            const shouldBlock = handleBlock(
                options,
                hostname,
                preCheckResult.reason,
                undefined,
                hostname
            );

            if (shouldBlock) {
                throw new Error(getErrorMessage(preCheckResult.reason, hostname));
            }
        }

        // Call the original createConnection
        const client = originalCreateConnection.call(this, connectionOptions, callback);

        // --- 2. Post-DNS Check (Lookup Event Check) ---
        // Only add listener if DNS rebinding detection is enabled
        if (detectDnsRebinding && client) {
            client.on('lookup', (err: Error | null, resolvedAddress: string | string[]) => {
                if (err) {
                    return; // DNS lookup failed, let it propagate naturally
                }

                // Check all resolved IPs (handle both single IP and array)
                const ipsToCheck = Array.isArray(resolvedAddress) ? resolvedAddress : [resolvedAddress];

                for (const ip of ipsToCheck) {
                    if (!ip) continue;

                    const postCheckResult = validateHost(ip, options);

                    if (!postCheckResult.safe && postCheckResult.reason) {
                        // For post-DNS check, the reason is DNS rebinding
                        const reason: BlockReason = 'dns_rebinding';

                        const shouldBlock = handleBlock(
                            options,
                            hostname,
                            reason,
                            ip,
                            hostname
                        );

                        if (shouldBlock) {
                            client.destroy(new Error(getErrorMessage(reason, `${hostname} -> ${ip}`)));
                            return;
                        }
                    }
                }
            });
        }

        return client;
    };

    return finalAgent;
}

export default ssrfAgentGuard;
module.exports = ssrfAgentGuard;
module.exports.default = ssrfAgentGuard;