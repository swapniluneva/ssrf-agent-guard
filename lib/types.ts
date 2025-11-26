// lib/types.ts
export interface Options {
    protocal?: string;
    metadataHosts?: string[];
    mode?: 'block' | 'report' | 'allow';
    policy?: PolicyOptions;
    blockCloudMetadata?: boolean;
    detectDnsRebinding?: boolean;
    logger?: (level: 'info' | 'warn' | 'error', msg: string, meta?: any) => void;
}

export interface PolicyOptions {
    allowDomains?: string[];
    denyDomains?: string[];
    denyTLD?: string[];
}

export interface BlockEvent {
    url: string;
    reason: string;
    ip?: string;
    timestamp: number;
}

export interface IsValidDomainOptions {
    subdomain?: boolean;
    wildcard?: boolean;
    allowUnicode?: boolean;
    topLevel?: boolean;
}

export const CLOUD_METADATA_HOSTS: string[] = [
    '169.254.169.254',
    '169.254.169.253',
    'metadata.google.internal',
    '169.254.170.2',
];
