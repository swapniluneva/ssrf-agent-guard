/**
 * Fastify example using ssrf-agent-guard for SSRF protection
 *
 * This example demonstrates how to protect your Fastify application
 * from SSRF attacks when making outbound HTTP requests.
 */

const Fastify = require('fastify');
const ssrfAgentGuard = require('ssrf-agent-guard');

const fastify = Fastify({ logger: true });

// Cloud metadata IPs to block
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', '169.254.169.253', '168.63.129.16',
  '169.254.170.2', '100.100.100.200', '169.254.0.0'
]);

/**
 * Simple URL validation (for pre-request checks)
 */
function validateUrl(urlString, options = {}) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // Check cloud metadata
    if (CLOUD_METADATA_IPS.has(hostname) ||
        hostname.includes('metadata.google') ||
        hostname.includes('kubernetes.default')) {
      return { valid: false, reason: 'cloud_metadata' };
    }

    // Check private IP ranges
    if (/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.|localhost$)/i.test(hostname)) {
      return { valid: false, reason: 'private_ip' };
    }

    // Check denied TLDs
    const deniedTLDs = options.policy?.denyTLD || [];
    const tld = hostname.split('.').pop()?.toLowerCase();
    if (tld && deniedTLDs.includes(tld)) {
      return { valid: false, reason: 'denied_tld' };
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, reason: 'invalid_url' };
  }
}

// Default SSRF protection options
const defaultSsrfOptions = {
  mode: 'block',
  blockCloudMetadata: true,
  detectDnsRebinding: true,
  policy: {
    denyDomains: ['*.internal.local'],
    denyTLD: ['local', 'internal', 'localhost']
  },
  logger: (level, msg, meta) => {
    fastify.log[level]({ ...meta, ssrfGuard: true }, msg);
  }
};

/**
 * Check if an error is from SSRF protection
 */
function isSsrfError(error) {
  const msg = error.message || '';
  return msg.includes('is not allowed') ||
         msg.includes('is denied') ||
         msg.includes('rebinding');
}

/**
 * Make an SSRF-protected HTTP request using native fetch with http.Agent
 */
async function protectedFetch(url, options = {}, ssrfOptions = defaultSsrfOptions) {
  // Create protected agent - this validates the URL and throws on SSRF
  const agent = ssrfAgentGuard(url, ssrfOptions);

  // Use dynamic import for node-fetch (supports agent option)
  const fetch = (await import('node-fetch')).default;

  return fetch(url, {
    ...options,
    agent
  });
}

// Schema for URL validation
const fetchSchema = {
  body: {
    type: 'object',
    required: ['url'],
    properties: {
      url: { type: 'string', format: 'uri' }
    }
  }
};

// Route: Fetch external URL (protected against SSRF)
fastify.post('/api/fetch', { schema: fetchSchema }, async (request, reply) => {
  const { url } = request.body;

  try {
    const response = await protectedFetch(url);
    const data = await response.json();

    return {
      status: response.status,
      data
    };
  } catch (error) {
    if (isSsrfError(error)) {
      request.log.warn({ url }, 'SSRF attempt blocked');
      return reply.code(403).send({
        error: 'Request blocked',
        reason: 'SSRF protection: The requested URL is not allowed'
      });
    }

    request.log.error({ error: error.message, url }, 'Failed to fetch URL');
    return reply.code(500).send({
      error: 'Failed to fetch URL',
      message: error.message
    });
  }
});

// Route: Webhook verification with custom policy
fastify.post('/api/webhooks/verify', async (request, reply) => {
  const { webhookUrl } = request.body;

  if (!webhookUrl) {
    return reply.code(400).send({ error: 'webhookUrl is required' });
  }

  try {
    const response = await protectedFetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ test: true, timestamp: Date.now() })
    });

    return {
      verified: true,
      status: response.status
    };
  } catch (error) {
    if (isSsrfError(error)) {
      return reply.code(403).send({
        verified: false,
        error: 'Webhook URL rejected: internal/private endpoints not allowed'
      });
    }

    return reply.code(400).send({
      verified: false,
      error: 'Webhook URL unreachable',
      message: error.message
    });
  }
});

// Route: URL validation endpoint (check without fetching)
fastify.post('/api/validate-url', async (request, reply) => {
  const { url } = request.body;

  if (!url) {
    return reply.code(400).send({ error: 'url is required' });
  }

  const result = validateUrl(url, defaultSsrfOptions);
  return { url, ...result };
});

// Route: Fetch with strict allowlist
fastify.post('/api/fetch-trusted', async (request, reply) => {
  const { url } = request.body;

  if (!url) {
    return reply.code(400).send({ error: 'url is required' });
  }

  // Strict policy - only allow specific trusted APIs
  const strictOptions = {
    ...defaultSsrfOptions,
    policy: {
      allowDomains: [
        'api.github.com',
        '*.githubusercontent.com',
        'httpbin.org'
      ]
    }
  };

  try {
    const response = await protectedFetch(url, {}, strictOptions);
    const data = await response.json();

    return {
      status: response.status,
      data
    };
  } catch (error) {
    if (isSsrfError(error)) {
      return reply.code(403).send({
        error: 'URL not in allowlist',
        allowedDomains: ['api.github.com', 'githubusercontent.com', 'httpbin.org']
      });
    }

    return reply.code(500).send({
      error: 'Failed to fetch URL',
      message: error.message
    });
  }
});

// Health check
fastify.get('/health', async () => {
  return { status: 'ok' };
});

// Start server
const start = async () => {
  try {
    const address = await fastify.listen({ port: 3000, host: '0.0.0.0' });
    console.log(`Fastify server running at ${address}`);
    console.log('\nTest endpoints:');
    console.log('  POST /api/fetch          - Fetch any URL (SSRF protected)');
    console.log('  POST /api/fetch-trusted  - Fetch from allowlisted URLs only');
    console.log('  POST /api/validate-url   - Validate URL without fetching');
    console.log('  POST /api/webhooks/verify - Verify webhook URL');
    console.log('\nExample requests:');
    console.log('  curl -X POST http://localhost:3000/api/fetch -H "Content-Type: application/json" -d \'{"url":"https://httpbin.org/get"}\'');
    console.log('  curl -X POST http://localhost:3000/api/validate-url -H "Content-Type: application/json" -d \'{"url":"http://169.254.169.254/"}\'');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
