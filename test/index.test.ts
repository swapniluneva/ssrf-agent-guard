import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { EventEmitter } from 'events';
import type { Options } from '../lib/types';

describe('ssrfAgentGuard', () => {
    let ssrfAgentGuard: (url: string, options?: any) => HttpAgent | HttpsAgent;
    let mockedValidateHost: jest.Mock;
    let originalHttpCreateConnection: typeof HttpAgent.prototype.createConnection;
    let originalHttpsCreateConnection: typeof HttpsAgent.prototype.createConnection;

    beforeAll(() => {
        // Save original createConnection methods
        originalHttpCreateConnection = HttpAgent.prototype.createConnection;
        originalHttpsCreateConnection = HttpsAgent.prototype.createConnection;
    });

    afterAll(() => {
        // Restore original createConnection methods
        HttpAgent.prototype.createConnection = originalHttpCreateConnection;
        HttpsAgent.prototype.createConnection = originalHttpsCreateConnection;
    });

    beforeEach(() => {
        // Reset modules to get fresh agent instances
        jest.resetModules();

        // Create mocks for utils functions
        mockedValidateHost = jest.fn().mockReturnValue({ safe: true });

        // Mock the utils module
        jest.doMock('../lib/utils', () => ({
            validateHost: mockedValidateHost,
            isCloudMetadata: jest.fn().mockReturnValue(false),
            validatePolicy: jest.fn().mockReturnValue({ safe: true }),
            matchesDomain: jest.fn().mockReturnValue(false),
            getTLD: jest.fn().mockReturnValue('com'),
        }));

        // Import fresh module - handle both ESM default export and CommonJS export
        const module = require('../index');
        ssrfAgentGuard = module.default || module;
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Agent Selection', () => {
        it('should return HttpsAgent for HTTPS URLs', () => {
            const agent = ssrfAgentGuard('https://example.com');
            expect(agent).toBeInstanceOf(HttpsAgent);
        });

        it('should return HttpAgent for HTTP URLs', () => {
            const agent = ssrfAgentGuard('http://example.com');
            expect(agent).toBeInstanceOf(HttpAgent);
        });

        it('should return HttpAgent by default for non-HTTPS URLs', () => {
            const agent = ssrfAgentGuard('ftp://example.com');
            expect(agent).toBeInstanceOf(HttpAgent);
        });

        it('should return HttpAgent for empty string', () => {
            const agent = ssrfAgentGuard('');
            expect(agent).toBeInstanceOf(HttpAgent);
        });

        it('should handle URLs with ports', () => {
            const httpsAgent = ssrfAgentGuard('https://example.com:8443');
            expect(httpsAgent).toBeInstanceOf(HttpsAgent);
        });

        it('should handle URLs with paths', () => {
            const agent = ssrfAgentGuard('https://example.com/api/v1/resource');
            expect(agent).toBeInstanceOf(HttpsAgent);
        });

        it('should return different agents for HTTP vs HTTPS', () => {
            const httpAgent = ssrfAgentGuard('http://example.com');
            const httpsAgent = ssrfAgentGuard('https://example.com');

            expect(httpAgent).not.toBe(httpsAgent);
            expect(httpAgent).toBeInstanceOf(HttpAgent);
            expect(httpsAgent).toBeInstanceOf(HttpsAgent);
        });
    });

    describe('Pre-DNS Validation', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            // Mock createConnection on prototypes before importing the module
            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            // Re-import with mocked createConnection
            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const module = require('../index');
            ssrfAgentGuard = module.default || module;
        });

        it('should throw error if host is not safe', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '10.0.0.1', port: 80 } as any, undefined as any);
            }).toThrow('Private IP address 10.0.0.1 is not allowed');
        });

        it('should not throw if host is safe', () => {
            mockedValidateHost.mockReturnValue({ safe: true });
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '8.8.8.8', port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should pass Options to validateHost', () => {
            const options: Options = { policy: { allowDomains: ['example.com'] } };
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com', options);
            agent.createConnection({ host: 'sub.example.com', port: 80 } as any, undefined as any);

            expect(mockedValidateHost).toHaveBeenCalledWith('sub.example.com', options);
        });

        it('should handle missing host option gracefully', () => {
            mockedValidateHost.mockReturnValue({ safe: true });
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should throw for cloud metadata IPs', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'cloud_metadata' });
            const agent = ssrfAgentGuard('http://169.254.169.254');

            expect(() => {
                agent.createConnection(
                    { host: '169.254.169.254', port: 80 } as any,
                    undefined as any,
                );
            }).toThrow('Cloud metadata endpoint 169.254.169.254 is not allowed');
        });

        it('should throw for private IP ranges', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '192.168.1.1', port: 80 } as any, undefined as any);
            }).toThrow('Private IP address 192.168.1.1 is not allowed');
        });

        it('should throw for localhost', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '127.0.0.1', port: 80 } as any, undefined as any);
            }).toThrow('Private IP address 127.0.0.1 is not allowed');
        });
    });

    describe('Post-DNS Validation', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const module = require('../index');
            ssrfAgentGuard = module.default || module;
        });

        it('should destroy connection if resolved IP is not safe', () => {
            mockedValidateHost
                .mockReturnValueOnce({ safe: true }) // Pre-DNS check passes
                .mockReturnValueOnce({ safe: false, reason: 'private_ip' }); // Post-DNS check fails

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'evil.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup resolving to a private IP
            mockSocket.emit('lookup', null, '10.0.0.1');

            expect(mockSocket.destroy).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: expect.stringContaining('DNS rebinding attack detected'),
                }),
            );
        });

        it('should not destroy connection if resolved IP is safe', () => {
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'safe.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup resolving to a public IP
            mockSocket.emit('lookup', null, '8.8.8.8');

            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should handle array of resolved addresses and check all IPs', () => {
            mockedValidateHost
                .mockReturnValueOnce({ safe: true }) // Pre-DNS check
                .mockReturnValueOnce({ safe: false, reason: 'private_ip' }); // Post-DNS check on first IP

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'multi.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup returning array of IPs
            mockSocket.emit('lookup', null, ['10.0.0.1', '10.0.0.2']);

            expect(mockSocket.destroy).toHaveBeenCalled();
        });

        it('should ignore lookup errors and not destroy connection', () => {
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'error.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup error
            const dnsError = new Error('ENOTFOUND');
            mockSocket.emit('lookup', dnsError, null);

            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should destroy connection for DNS rebinding attack', () => {
            mockedValidateHost
                .mockReturnValueOnce({ safe: true }) // Pre-DNS: "legitimate.com" looks safe
                .mockReturnValueOnce({ safe: false, reason: 'private_ip' }); // Post-DNS: but resolves to 127.0.0.1

            const agent = ssrfAgentGuard('http://legitimate.com');
            agent.createConnection({ host: 'legitimate.com', port: 80 } as any, undefined as any);

            // DNS rebinding: legitimate domain resolves to localhost
            mockSocket.emit('lookup', null, '127.0.0.1');

            expect(mockSocket.destroy).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: expect.stringContaining('DNS rebinding attack detected'),
                }),
            );
        });

        it('should register lookup event listener on socket', () => {
            mockedValidateHost.mockReturnValue({ safe: true });
            const onSpy = jest.spyOn(mockSocket, 'on');

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

            expect(onSpy).toHaveBeenCalledWith('lookup', expect.any(Function));
        });
    });

    describe('Fresh Agent Creation', () => {
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            const mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should create new agent for each call', () => {
            const agent1 = ssrfAgentGuard('http://example.com');
            const agent2 = ssrfAgentGuard('http://another.com');

            // Each call creates a new agent
            expect(agent1).not.toBe(agent2);
        });

        it('should create different agent types based on protocol', () => {
            const httpAgent = ssrfAgentGuard('http://example.com');
            const httpsAgent = ssrfAgentGuard('https://example.com');

            expect(httpAgent).toBeInstanceOf(HttpAgent);
            expect(httpsAgent).toBeInstanceOf(HttpsAgent);
            expect(httpAgent).not.toBe(httpsAgent);
        });

        it('should call original createConnection for each agent', () => {
            const agent1 = ssrfAgentGuard('http://example1.com');
            const agent2 = ssrfAgentGuard('http://example2.com');

            agent1.createConnection({ host: 'test1.com', port: 80 } as any, undefined as any);
            agent2.createConnection({ host: 'test2.com', port: 80 } as any, undefined as any);

            expect(mockCreateConnection).toHaveBeenCalledTimes(2);
        });
    });

    describe('createConnection Return Value', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should return the client socket from createConnection', () => {
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com');
            const result = agent.createConnection(
                { host: 'example.com', port: 80 } as any,
                undefined as any,
            );

            expect(result).toBe(mockSocket);
        });

        it('should handle null client from createConnection gracefully', () => {
            mockCreateConnection.mockReturnValue(null);
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should handle undefined client from createConnection gracefully', () => {
            mockCreateConnection.mockReturnValue(undefined);
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);
            }).not.toThrow();
        });
    });

    describe('Integration Scenarios', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should handle typical SSRF attack scenario', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });

            const agent = ssrfAgentGuard('http://internal-service.local');

            expect(() => {
                agent.createConnection({ host: '10.0.0.50', port: 80 } as any, undefined as any);
            }).toThrow('Private IP address 10.0.0.50 is not allowed');
        });

        it('should handle cloud metadata access attempt', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'cloud_metadata' });

            const agent = ssrfAgentGuard('http://169.254.169.254/latest/meta-data/');

            expect(() => {
                agent.createConnection(
                    { host: '169.254.169.254', port: 80 } as any,
                    undefined as any,
                );
            }).toThrow('Cloud metadata endpoint 169.254.169.254 is not allowed');
        });

        it('should allow legitimate external requests', () => {
            mockedValidateHost.mockReturnValue({ safe: true });

            const agent = ssrfAgentGuard('https://api.github.com');

            expect(() => {
                agent.createConnection(
                    { host: 'api.github.com', port: 443 } as any,
                    undefined as any,
                );
            }).not.toThrow();

            // Simulate successful DNS resolution to public IP
            mockSocket.emit('lookup', null, '140.82.121.6');
            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should protect against SSRF via localhost variations', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });

            const localhostVariants = ['127.0.0.1', '0.0.0.0', '127.0.0.2', '127.255.255.255'];

            localhostVariants.forEach((host) => {
                const agent = ssrfAgentGuard('http://example.com');
                expect(() => {
                    agent.createConnection({ host, port: 80 } as any, undefined as any);
                }).toThrow(`Private IP address ${host} is not allowed`);
            });
        });
    });

    describe('HTTPS Agent', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should apply same protections to HTTPS agent', () => {
            mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
            const agent = ssrfAgentGuard('https://secure.example.com');

            expect(() => {
                agent.createConnection({ host: '10.0.0.1', port: 443 } as any, undefined as any);
            }).toThrow('Private IP address 10.0.0.1 is not allowed');
        });

        it('should allow safe HTTPS connections', () => {
            mockedValidateHost.mockReturnValue({ safe: true });
            const agent = ssrfAgentGuard('https://api.example.com');

            expect(() => {
                agent.createConnection(
                    { host: 'api.example.com', port: 443 } as any,
                    undefined as any,
                );
            }).not.toThrow();
        });
    });

    describe('Options Features', () => {
        let mockSocket: EventEmitter & { destroy: jest.Mock };
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            mockedValidateHost = jest.fn().mockReturnValue({ safe: true });
            jest.doMock('../lib/utils', () => ({
                validateHost: mockedValidateHost,
                isCloudMetadata: jest.fn().mockReturnValue(false),
                validatePolicy: jest.fn().mockReturnValue({ safe: true }),
                matchesDomain: jest.fn().mockReturnValue(false),
                getTLD: jest.fn().mockReturnValue('com'),
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        describe('mode option', () => {
            it('should block requests in block mode (default)', () => {
                mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
                const agent = ssrfAgentGuard('http://example.com', { mode: 'block' });

                expect(() => {
                    agent.createConnection({ host: '10.0.0.1', port: 80 } as any, undefined as any);
                }).toThrow();
            });

            it('should allow requests in report mode but still validate', () => {
                mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
                const logger = jest.fn();
                const agent = ssrfAgentGuard('http://example.com', { mode: 'report', logger });

                expect(() => {
                    agent.createConnection({ host: '10.0.0.1', port: 80 } as any, undefined as any);
                }).not.toThrow();

                expect(logger).toHaveBeenCalledWith(
                    'warn',
                    expect.stringContaining('SSRF detected'),
                    expect.objectContaining({ reason: 'private_ip' }),
                );
            });

            it('should skip all checks in allow mode', () => {
                mockedValidateHost.mockReturnValue({ safe: false, reason: 'private_ip' });
                const agent = ssrfAgentGuard('http://example.com', { mode: 'allow' });

                // In allow mode, agent should not have patched createConnection
                expect(() => {
                    agent.createConnection({ host: '10.0.0.1', port: 80 } as any, undefined as any);
                }).not.toThrow();
            });
        });

        describe('logger option', () => {
            it('should call logger with error level when blocking', () => {
                mockedValidateHost.mockReturnValue({ safe: false, reason: 'cloud_metadata' });
                const logger = jest.fn();
                const agent = ssrfAgentGuard('http://example.com', { logger });

                expect(() => {
                    agent.createConnection(
                        { host: '169.254.169.254', port: 80 } as any,
                        undefined as any,
                    );
                }).toThrow();

                expect(logger).toHaveBeenCalledWith(
                    'error',
                    expect.stringContaining('SSRF blocked'),
                    expect.objectContaining({
                        url: '169.254.169.254',
                        reason: 'cloud_metadata',
                        timestamp: expect.any(Number),
                    }),
                );
            });

            it('should include BlockEvent data in logger call', () => {
                mockedValidateHost.mockReturnValue({ safe: false, reason: 'denied_domain' });
                const logger = jest.fn();
                const agent = ssrfAgentGuard('http://example.com', { logger });

                expect(() => {
                    agent.createConnection({ host: 'evil.com', port: 80 } as any, undefined as any);
                }).toThrow();

                const blockEvent = logger.mock.calls[0][2];
                expect(blockEvent).toHaveProperty('url');
                expect(blockEvent).toHaveProperty('reason');
                expect(blockEvent).toHaveProperty('timestamp');
            });
        });

        describe('detectDnsRebinding option', () => {
            it('should detect DNS rebinding by default', () => {
                mockedValidateHost
                    .mockReturnValueOnce({ safe: true }) // Pre-DNS check
                    .mockReturnValueOnce({ safe: false, reason: 'private_ip' }); // Post-DNS check

                const agent = ssrfAgentGuard('http://example.com');
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

                mockSocket.emit('lookup', null, '127.0.0.1');
                expect(mockSocket.destroy).toHaveBeenCalled();
            });

            it('should skip DNS rebinding check when disabled', () => {
                mockedValidateHost.mockReturnValue({ safe: true });
                const onSpy = jest.spyOn(mockSocket, 'on');

                const agent = ssrfAgentGuard('http://example.com', { detectDnsRebinding: false });
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

                // Should not register lookup listener
                expect(onSpy).not.toHaveBeenCalledWith('lookup', expect.any(Function));
            });
        });

        describe('protocol option', () => {
            it('should use protocol from options when provided', () => {
                const agent = ssrfAgentGuard('http://example.com', { protocol: 'https' });
                expect(agent).toBeInstanceOf(HttpsAgent);
            });

            it('should fall back to URL-based protocol detection', () => {
                const agent = ssrfAgentGuard('https://example.com');
                expect(agent).toBeInstanceOf(HttpsAgent);
            });
        });

        describe('policy options', () => {
            it('should pass policy to validateHost', () => {
                mockedValidateHost.mockReturnValue({ safe: true });
                const options: Options = {
                    policy: {
                        allowDomains: ['example.com'],
                        denyDomains: ['evil.com'],
                        denyTLD: ['local'],
                    },
                };

                const agent = ssrfAgentGuard('http://example.com', options);
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

                expect(mockedValidateHost).toHaveBeenCalledWith(
                    'example.com',
                    expect.objectContaining({ policy: options.policy }),
                );
            });
        });
    });
});
