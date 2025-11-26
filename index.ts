import { Agent as HttpAgent, AgentOptions as HttpAgentOptions } from 'http';
import { Agent as HttpsAgent, AgentOptions as HttpsAgentOptions } from 'https';
import { Duplex } from 'stream';

import { isSafeHost, isSafeIp } from './lib/utils';
import { IsValidDomainOptions } from './lib/types';

// Define the type for the Agent that this module will modify and return.
// It can be either an HttpAgent or an HttpsAgent.
type CustomAgent = HttpAgent | HttpsAgent;

// Instantiate the default agents
const httpAgent = new HttpAgent();
const httpsAgent = new HttpsAgent();

/**
 * Determines the correct Agent instance based on the input.
 * @param url The URL or another input to determine the agent type.
 * @returns The appropriate HttpAgent or HttpsAgent instance.
 */
const getAgent = (url: string): CustomAgent => {
    // If it's a string, check if it implies HTTPS
    if (typeof url === 'string' && url.startsWith('https')) {
        return httpsAgent;
    }
    // Default to HTTP agent
    return httpAgent;
};

// Define a Symbol for a unique property to prevent double-patching the agent.
const CREATE_CONNECTION = Symbol('createConnection');

/**
 * Patches an http.Agent or https.Agent to enforce an HOST/IP check
 * before and after a DNS lookup.
 *
 * @param url The URL or another input to determine the agent type.
 * @param isValidDomainOptions Options for validating domain names.
 * @returns The patched CustomAgent instance.
 */
export default function (url: string, isValidDomainOptions?: IsValidDomainOptions): CustomAgent {
    const finalAgent = getAgent(url);

    // Prevent patching the agent multiple times
    if ((finalAgent as any)[CREATE_CONNECTION]) {
        return finalAgent;
    }
    (finalAgent as any)[CREATE_CONNECTION] = true;

    // The original createConnection function from the Agent
    const createConnection = finalAgent.createConnection;

    // Patch the createConnection method on the agent
    finalAgent.createConnection =  (
        options: HttpAgentOptions | HttpsAgentOptions,
        fn?: (err: Error | null, stream: Duplex) => void,
    ) => {
        const { host: address } = options;
        // --- 1. Pre-DNS Check (Host/Address Check) ---
        // If the 'host' option is an IP address, check it immediately.
        // If it's a hostname, this check will usually pass (via defaultIpChecker).
        if (address && !isSafeHost(address, isValidDomainOptions)) {
            throw new Error(`DNS lookup ${address} is not allowed.`);
        }

        // Call the original createConnection
        // @ts-expect-error 'this' is not assignable to type 'HttpAgent | HttpsAgent'
        const client = createConnection.call(this, options, fn);

        // --- 2. Post-DNS Check (Lookup Event Check) ---
        // The 'lookup' event fires after the DNS lookup is complete
        // and provides the resolved IP address.
        client?.on('lookup', (err: Error | null, resolvedAddress: string | string[]) => {
            // If there was an error in lookup, or if the resolved IP is allowed, do nothing.
            if (err) {
                return;
            }

            // Ensure resolvedAddress is a string for the check (it's typically a string for simple lookups)
            const ipToCheck = Array.isArray(resolvedAddress) ? resolvedAddress[0] : resolvedAddress;

            if (!isSafeIp(ipToCheck)) {
                // If the resolved IP is NOT allowed (e.g., a private IP), destroy the connection.
                return client?.destroy(new Error(`DNS lookup ${ipToCheck} is not allowed.`));
            }
        });

        return client;
    };

    return finalAgent;
}
