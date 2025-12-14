import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { EventEmitter } from 'events';

describe('ssrfAgentGuard', () => {
    let ssrfAgentGuard: (url: string, options?: any) => HttpAgent | HttpsAgent;
    let mockedIsSafeHost: jest.Mock;
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

        // Create mock for isSafeHost
        mockedIsSafeHost = jest.fn().mockReturnValue(true);

        // Mock the utils module
        jest.doMock('../lib/utils', () => ({
            isSafeHost: mockedIsSafeHost,
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
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const module = require('../index');
            ssrfAgentGuard = module.default || module;
        });

        it('should throw error if host is not safe', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '10.0.0.1', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 10.0.0.1 is not allowed.');
        });

        it('should not throw if host is safe', () => {
            mockedIsSafeHost.mockReturnValue(true);
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '8.8.8.8', port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should pass isValidDomainOptions to isSafeHost', () => {
            const options = { subdomain: true, allowUnicode: false };
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('http://example.com', options);
            agent.createConnection({ host: 'sub.example.com', port: 80 } as any, undefined as any);

            expect(mockedIsSafeHost).toHaveBeenCalledWith('sub.example.com', options);
        });

        it('should handle missing host option gracefully', () => {
            mockedIsSafeHost.mockReturnValue(true);
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should throw for cloud metadata IPs', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('http://169.254.169.254');

            expect(() => {
                agent.createConnection({ host: '169.254.169.254', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 169.254.169.254 is not allowed.');
        });

        it('should throw for private IP ranges', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '192.168.1.1', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 192.168.1.1 is not allowed.');
        });

        it('should throw for localhost', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: '127.0.0.1', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 127.0.0.1 is not allowed.');
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
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const module = require('../index');
            ssrfAgentGuard = module.default || module;
        });

        it('should destroy connection if resolved IP is not safe', () => {
            mockedIsSafeHost
                .mockReturnValueOnce(true) // Pre-DNS check passes
                .mockReturnValueOnce(false); // Post-DNS check fails

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'evil.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup resolving to a private IP
            mockSocket.emit('lookup', null, '10.0.0.1');

            expect(mockSocket.destroy).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: 'DNS lookup 10.0.0.1 is not allowed.',
                })
            );
        });

        it('should not destroy connection if resolved IP is safe', () => {
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'safe.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup resolving to a public IP
            mockSocket.emit('lookup', null, '8.8.8.8');

            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should handle array of resolved addresses', () => {
            mockedIsSafeHost
                .mockReturnValueOnce(true) // Pre-DNS check
                .mockReturnValueOnce(false); // Post-DNS check on first IP in array

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'multi.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup returning array of IPs (takes first one)
            mockSocket.emit('lookup', null, ['10.0.0.1', '10.0.0.2']);

            expect(mockedIsSafeHost).toHaveBeenLastCalledWith('10.0.0.1', undefined);
            expect(mockSocket.destroy).toHaveBeenCalled();
        });

        it('should ignore lookup errors and not destroy connection', () => {
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'error.com', port: 80 } as any, undefined as any);

            // Simulate DNS lookup error
            const dnsError = new Error('ENOTFOUND');
            mockSocket.emit('lookup', dnsError, null);

            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should destroy connection for DNS rebinding attack', () => {
            mockedIsSafeHost
                .mockReturnValueOnce(true) // Pre-DNS: "legitimate.com" looks safe
                .mockReturnValueOnce(false); // Post-DNS: but resolves to 127.0.0.1

            const agent = ssrfAgentGuard('http://legitimate.com');
            agent.createConnection({ host: 'legitimate.com', port: 80 } as any, undefined as any);

            // DNS rebinding: legitimate domain resolves to localhost
            mockSocket.emit('lookup', null, '127.0.0.1');

            expect(mockSocket.destroy).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: 'DNS lookup 127.0.0.1 is not allowed.',
                })
            );
        });

        it('should register lookup event listener on socket', () => {
            mockedIsSafeHost.mockReturnValue(true);
            const onSpy = jest.spyOn(mockSocket, 'on');

            const agent = ssrfAgentGuard('http://example.com');
            agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

            expect(onSpy).toHaveBeenCalledWith('lookup', expect.any(Function));
        });
    });

    describe('Patch Prevention', () => {
        let mockCreateConnection: jest.Mock;

        beforeEach(() => {
            const mockSocket = Object.assign(new EventEmitter(), {
                destroy: jest.fn(),
            });
            mockCreateConnection = jest.fn().mockReturnValue(mockSocket);

            HttpAgent.prototype.createConnection = mockCreateConnection;
            HttpsAgent.prototype.createConnection = mockCreateConnection;

            jest.resetModules();
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should not patch agent multiple times', () => {
            const agent1 = ssrfAgentGuard('http://example.com');
            const agent2 = ssrfAgentGuard('http://another.com');

            // Both should return the same patched agent instance
            expect(agent1).toBe(agent2);
        });

        it('should return same HTTPS agent instance on multiple calls', () => {
            const agent1 = ssrfAgentGuard('https://example.com');
            const agent2 = ssrfAgentGuard('https://another.com');

            expect(agent1).toBe(agent2);
        });

        it('should only patch createConnection once per agent type', () => {
            // Get HTTP agent multiple times
            ssrfAgentGuard('http://example1.com');
            ssrfAgentGuard('http://example2.com');
            ssrfAgentGuard('http://example3.com');

            const agent = ssrfAgentGuard('http://example.com');

            // Call createConnection - original should only be called once per invocation
            agent.createConnection({ host: 'test.com', port: 80 } as any, undefined as any);

            expect(mockCreateConnection).toHaveBeenCalledTimes(1);
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
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should return the client socket from createConnection', () => {
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('http://example.com');
            const result = agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);

            expect(result).toBe(mockSocket);
        });

        it('should handle null client from createConnection gracefully', () => {
            mockCreateConnection.mockReturnValue(null);
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('http://example.com');

            expect(() => {
                agent.createConnection({ host: 'example.com', port: 80 } as any, undefined as any);
            }).not.toThrow();
        });

        it('should handle undefined client from createConnection gracefully', () => {
            mockCreateConnection.mockReturnValue(undefined);
            mockedIsSafeHost.mockReturnValue(true);

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
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should handle typical SSRF attack scenario', () => {
            mockedIsSafeHost.mockReturnValue(false);

            const agent = ssrfAgentGuard('http://internal-service.local');

            expect(() => {
                agent.createConnection({ host: '10.0.0.50', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 10.0.0.50 is not allowed.');
        });

        it('should handle cloud metadata access attempt', () => {
            mockedIsSafeHost.mockReturnValue(false);

            const agent = ssrfAgentGuard('http://169.254.169.254/latest/meta-data/');

            expect(() => {
                agent.createConnection({ host: '169.254.169.254', port: 80 } as any, undefined as any);
            }).toThrow('DNS lookup 169.254.169.254 is not allowed.');
        });

        it('should allow legitimate external requests', () => {
            mockedIsSafeHost.mockReturnValue(true);

            const agent = ssrfAgentGuard('https://api.github.com');

            expect(() => {
                agent.createConnection({ host: 'api.github.com', port: 443 } as any, undefined as any);
            }).not.toThrow();

            // Simulate successful DNS resolution to public IP
            mockSocket.emit('lookup', null, '140.82.121.6');
            expect(mockSocket.destroy).not.toHaveBeenCalled();
        });

        it('should protect against SSRF via localhost variations', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('http://example.com');

            const localhostVariants = [
                '127.0.0.1',
                '0.0.0.0',
                '127.0.0.2',
                '127.255.255.255',
            ];

            localhostVariants.forEach((host) => {
                expect(() => {
                    agent.createConnection({ host, port: 80 } as any, undefined as any);
                }).toThrow(`DNS lookup ${host} is not allowed.`);
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
            jest.doMock('../lib/utils', () => ({
                isSafeHost: mockedIsSafeHost,
            }));
            const mod = require('../index');
            ssrfAgentGuard = mod.default || mod;
        });

        it('should apply same protections to HTTPS agent', () => {
            mockedIsSafeHost.mockReturnValue(false);
            const agent = ssrfAgentGuard('https://secure.example.com');

            expect(() => {
                agent.createConnection({ host: '10.0.0.1', port: 443 } as any, undefined as any);
            }).toThrow('DNS lookup 10.0.0.1 is not allowed.');
        });

        it('should allow safe HTTPS connections', () => {
            mockedIsSafeHost.mockReturnValue(true);
            const agent = ssrfAgentGuard('https://api.example.com');

            expect(() => {
                agent.createConnection({ host: 'api.example.com', port: 443 } as any, undefined as any);
            }).not.toThrow();
        });
    });
});
