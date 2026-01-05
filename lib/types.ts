// lib/types.ts

/**
 * Block reasons for SSRF detection
 */
export type BlockReason =
    | 'private_ip'
    | 'cloud_metadata'
    | 'invalid_domain'
    | 'dns_rebinding'
    | 'denied_domain'
    | 'denied_tld'
    | 'not_allowed_domain';

/**
 * Main configuration options for ssrf-agent-guard
 */
export interface Options {
    /** Protocol hint (http or https) - typically inferred from URL */
    protocol?: string;
    /** Custom cloud metadata hosts to block (merged with defaults) */
    metadataHosts?: string[];
    /**
     * Operation mode:
     * - 'block': Block and throw error (default)
     * - 'report': Log but allow the request
     * - 'allow': Disable all checks (for debugging)
     */
    mode?: 'block' | 'report' | 'allow';
    /** Domain/TLD policy options */
    policy?: PolicyOptions;
    /** Whether to block cloud metadata endpoints (default: true) */
    blockCloudMetadata?: boolean;
    /** Whether to detect DNS rebinding attacks (default: true) */
    detectDnsRebinding?: boolean;
    /** Logger callback for blocked requests and warnings */
    logger?: (level: 'info' | 'warn' | 'error', msg: string, meta?: BlockEvent) => void;
}

/**
 * Policy options for domain-based filtering
 */
export interface PolicyOptions {
    /** Domains explicitly allowed (bypasses other checks) */
    allowDomains?: string[];
    /** Domains explicitly denied */
    denyDomains?: string[];
    /** Top-level domains to deny (e.g., ['local', 'internal']) */
    denyTLD?: string[];
}

/**
 * Event data passed to logger when a request is blocked or flagged
 */
export interface BlockEvent {
    /** The original URL or hostname */
    url: string;
    /** The reason for blocking */
    reason: BlockReason;
    /** The resolved IP address (if available) */
    ip?: string;
    /** Timestamp of the event */
    timestamp: number;
    /** The original hostname before DNS resolution */
    hostname?: string;
}

/**
 * Default cloud metadata hosts to block.
 * Includes AWS, GCP, Azure, Oracle Cloud, DigitalOcean, and Kubernetes.
 */
export const CLOUD_METADATA_HOSTS: Set<string> = new Set([
    // AWS EC2 metadata service
    '169.254.169.254',
    '169.254.169.253',
    // GCP metadata service
    'metadata.google.internal',
    'metadata.goog',
    // Azure IMDS
    '169.254.169.254',
    '168.63.129.16',
    // ECS task metadata (AWS Fargate)
    '169.254.170.2',
    // Kubernetes metadata
    'kubernetes.default',
    'kubernetes.default.svc',
    'kubernetes.default.svc.cluster.local',
    // Oracle Cloud
    '169.254.169.254',
    // DigitalOcean
    '169.254.169.254',
    // Alibaba Cloud
    '100.100.100.200',
    // Link-local for metadata
    '169.254.0.0',
]);

/**
 * Result of host validation check
 */
export interface ValidationResult {
    safe: boolean;
    reason?: BlockReason;
}
