import {
    validateHost,
    validatePolicy,
    matchesDomain,
    getTLD,
    isCloudMetadata,
    isIp,
    isPublicIp,
} from '../lib/utils';

describe('validateHost', () => {
    describe('with Options', () => {
        it('should return safe:true for allowed domains', () => {
            const result = validateHost('example.com');
            expect(result.safe).toBe(true);
        });

        it('should return reason for private IPs', () => {
            const result = validateHost('10.0.0.1');
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('private_ip');
        });

        it('should return reason for cloud metadata', () => {
            const result = validateHost('169.254.169.254');
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('cloud_metadata');
        });

        it('should return reason for invalid domains', () => {
            const result = validateHost('-invalid.com');
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('invalid_domain');
        });

        it('should allow disabling cloud metadata blocking', () => {
            const result = validateHost('169.254.169.254', { blockCloudMetadata: false });
            // Still blocked as private IP
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('private_ip');
        });

        it('should check custom metadata hosts', () => {
            const result = validateHost('custom.metadata.local', {
                metadataHosts: ['custom.metadata.local'],
            });
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('cloud_metadata');
        });
    });
});

describe('validatePolicy', () => {
    describe('allowDomains', () => {
        it('should allow domains in allowDomains list', () => {
            const result = validatePolicy('example.com', {
                allowDomains: ['example.com'],
            });
            expect(result.safe).toBe(true);
        });

        it('should deny domains not in allowDomains list when list is specified', () => {
            const result = validatePolicy('other.com', {
                allowDomains: ['example.com'],
            });
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('not_allowed_domain');
        });

        it('should allow subdomains when parent domain is in allowDomains', () => {
            const result = validatePolicy('sub.example.com', {
                allowDomains: ['example.com'],
            });
            expect(result.safe).toBe(true);
        });

        it('should allow wildcard patterns in allowDomains', () => {
            const result = validatePolicy('api.example.com', {
                allowDomains: ['*.example.com'],
            });
            expect(result.safe).toBe(true);
        });
    });

    describe('denyDomains', () => {
        it('should deny domains in denyDomains list', () => {
            const result = validatePolicy('evil.com', {
                denyDomains: ['evil.com'],
            });
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('denied_domain');
        });

        it('should allow domains not in denyDomains list', () => {
            const result = validatePolicy('good.com', {
                denyDomains: ['evil.com'],
            });
            expect(result.safe).toBe(true);
        });

        it('should deny subdomains when parent domain is in denyDomains', () => {
            const result = validatePolicy('sub.evil.com', {
                denyDomains: ['evil.com'],
            });
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('denied_domain');
        });
    });

    describe('denyTLD', () => {
        it('should deny domains with blocked TLDs', () => {
            const result = validatePolicy('internal.local', {
                denyTLD: ['local', 'internal'],
            });
            expect(result.safe).toBe(false);
            expect(result.reason).toBe('denied_tld');
        });

        it('should allow domains with non-blocked TLDs', () => {
            const result = validatePolicy('example.com', {
                denyTLD: ['local', 'internal'],
            });
            expect(result.safe).toBe(true);
        });

        it('should be case-insensitive for TLDs', () => {
            const result = validatePolicy('example.LOCAL', {
                denyTLD: ['local'],
            });
            expect(result.safe).toBe(false);
        });
    });

    describe('no policy', () => {
        it('should allow all domains when no policy is provided', () => {
            const result = validatePolicy('anything.com');
            expect(result.safe).toBe(true);
        });

        it('should allow all domains when empty policy is provided', () => {
            const result = validatePolicy('anything.com', {});
            expect(result.safe).toBe(true);
        });
    });
});

describe('matchesDomain', () => {
    it('should match exact domains', () => {
        expect(matchesDomain('example.com', 'example.com')).toBe(true);
    });

    it('should match subdomains', () => {
        expect(matchesDomain('sub.example.com', 'example.com')).toBe(true);
        expect(matchesDomain('deep.sub.example.com', 'example.com')).toBe(true);
    });

    it('should match wildcard patterns', () => {
        expect(matchesDomain('sub.example.com', '*.example.com')).toBe(true);
        expect(matchesDomain('example.com', '*.example.com')).toBe(true);
    });

    it('should not match different domains', () => {
        expect(matchesDomain('other.com', 'example.com')).toBe(false);
        expect(matchesDomain('notexample.com', 'example.com')).toBe(false);
    });

    it('should be case-insensitive', () => {
        expect(matchesDomain('EXAMPLE.COM', 'example.com')).toBe(true);
        expect(matchesDomain('example.com', 'EXAMPLE.COM')).toBe(true);
    });
});

describe('getTLD', () => {
    it('should extract TLD from domain', () => {
        expect(getTLD('example.com')).toBe('com');
        expect(getTLD('example.org')).toBe('org');
        expect(getTLD('example.co.uk')).toBe('uk');
    });

    it('should handle subdomains', () => {
        expect(getTLD('sub.example.com')).toBe('com');
    });

    it('should be case-insensitive', () => {
        expect(getTLD('example.COM')).toBe('com');
    });

    it('should handle edge cases', () => {
        expect(getTLD('localhost')).toBe('localhost');
        expect(getTLD('')).toBe('');
    });
});

describe('isCloudMetadata', () => {
    it('should detect default cloud metadata hosts', () => {
        expect(isCloudMetadata('169.254.169.254')).toBe(true);
        expect(isCloudMetadata('metadata.google.internal')).toBe(true);
    });

    it('should detect custom metadata hosts', () => {
        expect(isCloudMetadata('custom.metadata', ['custom.metadata'])).toBe(true);
    });

    it('should return false for non-metadata hosts', () => {
        expect(isCloudMetadata('example.com')).toBe(false);
    });
});

describe('isIp', () => {
    it('should detect valid IPv4 addresses', () => {
        expect(isIp('8.8.8.8')).toBe(true);
        expect(isIp('192.168.1.1')).toBe(true);
    });

    it('should detect valid IPv6 addresses', () => {
        expect(isIp('::1')).toBe(true);
        expect(isIp('2001:4860:4860::8888')).toBe(true);
    });

    it('should return false for domain names', () => {
        expect(isIp('example.com')).toBe(false);
    });
});

describe('isPublicIp', () => {
    it('should return true for public IPs', () => {
        expect(isPublicIp('8.8.8.8')).toBe(true);
        expect(isPublicIp('93.184.216.34')).toBe(true);
    });

    it('should return false for private IPs', () => {
        expect(isPublicIp('10.0.0.1')).toBe(false);
        expect(isPublicIp('192.168.1.1')).toBe(false);
        expect(isPublicIp('127.0.0.1')).toBe(false);
    });
});
