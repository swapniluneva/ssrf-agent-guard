/**
 * Express.js example using ssrf-agent-guard for SSRF protection
 *
 * This example demonstrates how to protect your Express application
 * from SSRF attacks when making outbound HTTP requests.
 */

const express = require('express');
const axios = require('axios');
const ssrfAgentGuard = require('ssrf-agent-guard');

const app = express();
app.use(express.json());

// Configuration for ssrf-agent-guard
const ssrfOptions = {
  mode: 'block',                    // 'block' | 'report' | 'allow'
  blockCloudMetadata: true,         // Block AWS/GCP/Azure metadata endpoints
  detectDnsRebinding: true,         // Detect DNS rebinding attacks
  policy: {
    // Uncomment to restrict to specific domains only:
    // allowDomains: ['*.trusted-api.com', 'api.example.com'],
    denyDomains: ['*.internal.local'],
    denyTLD: ['local', 'internal', 'localhost']
  },
  logger: (level, msg, meta) => {
    console.log(`[SSRF-Guard][${level}] ${msg}`, meta);
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
 * Helper function to make protected HTTP requests
 * @param {string} url - The URL to fetch
 * @param {object} options - Additional axios options
 */
async function protectedFetch(url, options = {}) {
  const agent = ssrfAgentGuard(url, ssrfOptions);

  return axios({
    url,
    httpAgent: agent,
    httpsAgent: agent,
    ...options
  });
}

// Route: Fetch external URL (protected against SSRF)
app.post('/api/fetch', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const response = await protectedFetch(url, {
      method: 'GET',
      timeout: 10000
    });

    res.json({
      status: response.status,
      data: response.data
    });
  } catch (error) {
    // Check if this was an SSRF block
    if (isSsrfError(error)) {
      console.warn(`SSRF attempt blocked: ${url}`);
      return res.status(403).json({
        error: 'Request blocked',
        reason: 'SSRF protection: The requested URL is not allowed'
      });
    }

    // Handle other errors
    res.status(500).json({
      error: 'Failed to fetch URL',
      message: error.message
    });
  }
});

// Route: Webhook verification example
app.post('/api/webhooks/verify', async (req, res) => {
  const { webhookUrl } = req.body;

  if (!webhookUrl) {
    return res.status(400).json({ error: 'webhookUrl is required' });
  }

  try {
    // Verify webhook endpoint is reachable and safe
    const response = await protectedFetch(webhookUrl, {
      method: 'POST',
      data: { test: true, timestamp: Date.now() },
      timeout: 5000
    });

    res.json({
      verified: true,
      status: response.status
    });
  } catch (error) {
    if (isSsrfError(error)) {
      return res.status(403).json({
        verified: false,
        error: 'Webhook URL rejected: internal/private endpoints not allowed'
      });
    }

    res.status(400).json({
      verified: false,
      error: 'Webhook URL unreachable',
      message: error.message
    });
  }
});

// Route: Image proxy example with strict allowlist
app.get('/api/proxy/image', async (req, res) => {
  const { src } = req.query;

  if (!src) {
    return res.status(400).json({ error: 'src parameter is required' });
  }

  // Strict policy for image proxy - only allow specific CDN domains
  const imageProxyOptions = {
    ...ssrfOptions,
    policy: {
      allowDomains: [
        '*.cloudinary.com',
        '*.imgix.net',
        '*.githubusercontent.com',
        'images.unsplash.com'
      ]
    }
  };

  try {
    const agent = ssrfAgentGuard(src, imageProxyOptions);
    const response = await axios({
      url: src,
      method: 'GET',
      responseType: 'arraybuffer',
      httpAgent: agent,
      httpsAgent: agent,
      timeout: 10000
    });

    res.set('Content-Type', response.headers['content-type']);
    res.send(response.data);
  } catch (error) {
    if (isSsrfError(error)) {
      return res.status(403).json({
        error: 'Image source not allowed',
        allowedDomains: ['cloudinary.com', 'imgix.net', 'githubusercontent.com', 'unsplash.com']
      });
    }

    res.status(500).json({
      error: 'Failed to fetch image',
      message: error.message
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Express server running on port ${PORT}`);
  console.log('\nTest endpoints:');
  console.log('  POST /api/fetch          - Fetch any URL (SSRF protected)');
  console.log('  POST /api/webhooks/verify - Verify webhook URL');
  console.log('  GET  /api/proxy/image    - Proxy images from allowed CDNs');
  console.log('\nExample requests:');
  console.log('  curl -X POST http://localhost:3000/api/fetch -H "Content-Type: application/json" -d \'{"url":"https://httpbin.org/get"}\'');
  console.log('  curl -X POST http://localhost:3000/api/fetch -H "Content-Type: application/json" -d \'{"url":"http://169.254.169.254/latest/meta-data/"}\'  # Blocked');
});
