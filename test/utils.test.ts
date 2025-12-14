import { isSafeHost } from '../lib/utils';
import { CLOUD_METADATA_HOSTS } from '../lib/types';

describe('isSafeHost', () => {
    describe('Cloud Metadata Hosts', () => {
        it('should block AWS metadata endpoint (169.254.169.254)', () => {
            expect(isSafeHost('169.254.169.254')).toBe(false);
        });

        it('should block AWS alternate metadata endpoint (169.254.169.253)', () => {
            expect(isSafeHost('169.254.169.253')).toBe(false);
        });

        it('should block GCP metadata endpoint (metadata.google.internal)', () => {
            expect(isSafeHost('metadata.google.internal')).toBe(false);
        });

        it('should block Azure metadata endpoint (169.254.170.2)', () => {
            expect(isSafeHost('169.254.170.2')).toBe(false);
        });

        it('should block all hosts in CLOUD_METADATA_HOSTS constant', () => {
            CLOUD_METADATA_HOSTS.forEach((host) => {
                expect(isSafeHost(host)).toBe(false);
            });
        });
    });

    describe('Private IP Addresses', () => {
        it('should block localhost (127.0.0.1)', () => {
            expect(isSafeHost('127.0.0.1')).toBe(false);
        });

        it('should block loopback range (127.x.x.x)', () => {
            expect(isSafeHost('127.0.0.2')).toBe(false);
            expect(isSafeHost('127.255.255.255')).toBe(false);
        });

        it('should block 10.x.x.x private range', () => {
            expect(isSafeHost('10.0.0.1')).toBe(false);
            expect(isSafeHost('10.255.255.255')).toBe(false);
            expect(isSafeHost('10.10.10.10')).toBe(false);
        });

        it('should block 172.16.x.x - 172.31.x.x private range', () => {
            expect(isSafeHost('172.16.0.1')).toBe(false);
            expect(isSafeHost('172.20.0.1')).toBe(false);
            expect(isSafeHost('172.31.255.255')).toBe(false);
        });

        it('should block 192.168.x.x private range', () => {
            expect(isSafeHost('192.168.0.1')).toBe(false);
            expect(isSafeHost('192.168.1.1')).toBe(false);
            expect(isSafeHost('192.168.255.255')).toBe(false);
        });

        it('should block link-local addresses (169.254.x.x)', () => {
            expect(isSafeHost('169.254.0.1')).toBe(false);
            expect(isSafeHost('169.254.255.255')).toBe(false);
        });

        it('should block 0.0.0.0', () => {
            expect(isSafeHost('0.0.0.0')).toBe(false);
        });

        it('should block broadcast address (255.255.255.255)', () => {
            expect(isSafeHost('255.255.255.255')).toBe(false);
        });
    });

    describe('IPv6 Addresses', () => {
        it('should block IPv6 loopback (::1)', () => {
            expect(isSafeHost('::1')).toBe(false);
        });

        it('should block IPv6 unspecified address (::)', () => {
            expect(isSafeHost('::')).toBe(false);
        });

        it('should block IPv6 link-local addresses (fe80::)', () => {
            expect(isSafeHost('fe80::1')).toBe(false);
            expect(isSafeHost('fe80::abcd:1234')).toBe(false);
        });

        it('should block IPv6 unique local addresses (fc00::/fd00::)', () => {
            expect(isSafeHost('fc00::1')).toBe(false);
            expect(isSafeHost('fd00::1')).toBe(false);
        });

        it('should allow public IPv6 addresses', () => {
            expect(isSafeHost('2001:4860:4860::8888')).toBe(true); // Google DNS
            expect(isSafeHost('2606:4700:4700::1111')).toBe(true); // Cloudflare DNS
        });
    });

    describe('Public IP Addresses', () => {
        it('should allow Google DNS (8.8.8.8)', () => {
            expect(isSafeHost('8.8.8.8')).toBe(true);
        });

        it('should allow Cloudflare DNS (1.1.1.1)', () => {
            expect(isSafeHost('1.1.1.1')).toBe(true);
        });

        it('should allow common public IP addresses', () => {
            expect(isSafeHost('93.184.216.34')).toBe(true); // example.com
            expect(isSafeHost('151.101.1.140')).toBe(true); // reddit.com
            expect(isSafeHost('185.199.108.153')).toBe(true); // github.com
        });

        it('should allow IPs just outside private ranges', () => {
            expect(isSafeHost('11.0.0.1')).toBe(true); // Just after 10.x.x.x
            expect(isSafeHost('172.15.255.255')).toBe(true); // Just before 172.16.x.x
            expect(isSafeHost('172.32.0.1')).toBe(true); // Just after 172.31.x.x
            expect(isSafeHost('192.167.255.255')).toBe(true); // Just before 192.168.x.x
        });
    });

    describe('Valid Domain Names', () => {
        it('should allow simple domain names', () => {
            expect(isSafeHost('example.com')).toBe(true);
            expect(isSafeHost('google.com')).toBe(true);
            expect(isSafeHost('github.com')).toBe(true);
        });

        it('should allow subdomains by default', () => {
            expect(isSafeHost('www.example.com')).toBe(true);
            expect(isSafeHost('api.github.com')).toBe(true);
            expect(isSafeHost('sub.domain.example.com')).toBe(true);
        });

        it('should allow domains with hyphens', () => {
            expect(isSafeHost('my-domain.com')).toBe(true);
            expect(isSafeHost('sub-domain.example-site.com')).toBe(true);
        });

        it('should allow domains with numbers', () => {
            expect(isSafeHost('web3.com')).toBe(true);
            expect(isSafeHost('123.example.com')).toBe(true);
        });

        it('should allow various TLDs', () => {
            expect(isSafeHost('example.org')).toBe(true);
            expect(isSafeHost('example.net')).toBe(true);
            expect(isSafeHost('example.io')).toBe(true);
            expect(isSafeHost('example.co.uk')).toBe(true);
        });
    });

    describe('Invalid Domain Names', () => {
        it('should reject domains starting with hyphen', () => {
            expect(isSafeHost('-example.com')).toBe(false);
        });

        it('should reject domains ending with hyphen', () => {
            expect(isSafeHost('example-.com')).toBe(false);
        });

        it('should reject domains with invalid characters', () => {
            expect(isSafeHost('example@.com')).toBe(false);
            expect(isSafeHost('example!.com')).toBe(false);
            expect(isSafeHost('example$.com')).toBe(false);
        });

        it('should reject empty string', () => {
            expect(isSafeHost('')).toBe(false);
        });

        it('should reject domains with spaces', () => {
            expect(isSafeHost('example .com')).toBe(false);
            expect(isSafeHost(' example.com')).toBe(false);
        });

        it('should reject double dots in domain', () => {
            expect(isSafeHost('example..com')).toBe(false);
        });
    });

    describe('Unicode Domains', () => {
        it('should allow punycode domains (ASCII-compatible encoding)', () => {
            // Punycode is ASCII-compatible, so it's valid regardless of allowUnicode
            expect(isSafeHost('xn--n3h.com')).toBe(true);
        });

        it('should handle allowUnicode option', () => {
            // Both should work for ASCII-compatible punycode
            expect(isSafeHost('xn--n3h.com', { allowUnicode: true })).toBe(true);
            expect(isSafeHost('xn--n3h.com', { allowUnicode: false })).toBe(true);
        });
    });

    describe('Options', () => {
        it('should respect subdomain option', () => {
            expect(isSafeHost('sub.example.com', { subdomain: true })).toBe(true);
            expect(isSafeHost('sub.example.com', { subdomain: false })).toBe(false);
        });

        it('should respect wildcard option', () => {
            expect(isSafeHost('*.example.com', { wildcard: true })).toBe(true);
            expect(isSafeHost('*.example.com', { wildcard: false })).toBe(false);
        });

        it('should merge options with defaults', () => {
            // Default is subdomain: true, allowUnicode: false
            expect(isSafeHost('sub.example.com', { allowUnicode: true })).toBe(true);
        });
    });

    describe('Edge Cases', () => {
        it('should handle localhost hostname', () => {
            expect(isSafeHost('localhost')).toBe(false);
        });

        it('should handle IP-like strings that are invalid', () => {
            expect(isSafeHost('999.999.999.999')).toBe(false);
            expect(isSafeHost('256.256.256.256')).toBe(false);
        });

        it('should handle very long domain names', () => {
            const longDomain = 'a'.repeat(63) + '.com';
            expect(isSafeHost(longDomain)).toBe(true);
        });

        it('should reject domain labels longer than 63 characters', () => {
            const tooLongLabel = 'a'.repeat(64) + '.com';
            expect(isSafeHost(tooLongLabel)).toBe(false);
        });
    });
});
