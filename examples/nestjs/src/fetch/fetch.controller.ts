import { Controller, Post, Body, HttpException, HttpStatus } from '@nestjs/common';
import { SsrfHttpService } from '../ssrf-http/ssrf-http.service';

interface FetchDto {
  url: string;
}

interface WebhookVerifyDto {
  webhookUrl: string;
}

@Controller()
export class FetchController {
  constructor(private readonly ssrfHttpService: SsrfHttpService) {}

  /**
   * Fetch any URL with SSRF protection
   */
  @Post('fetch')
  async fetch(@Body() body: FetchDto) {
    if (!body.url) {
      throw new HttpException('URL is required', HttpStatus.BAD_REQUEST);
    }

    try {
      const response = await this.ssrfHttpService.get(body.url, {
        timeout: 10000,
      });

      return {
        status: response.status,
        data: response.data,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Failed to fetch URL',
          message: error.message,
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Fetch from allowlisted URLs only
   */
  @Post('fetch-trusted')
  async fetchTrusted(@Body() body: FetchDto) {
    if (!body.url) {
      throw new HttpException('URL is required', HttpStatus.BAD_REQUEST);
    }

    // Strict policy - only allow specific trusted APIs
    const strictPolicy = {
      policy: {
        allowDomains: ['api.github.com', '*.githubusercontent.com', 'httpbin.org'],
      },
    };

    try {
      const response = await this.ssrfHttpService.requestWithPolicy(
        { url: body.url, method: 'GET', timeout: 10000 },
        strictPolicy,
      );

      return {
        status: response.status,
        data: response.data,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          error: 'Failed to fetch URL',
          message: error.message,
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Validate URL without fetching
   */
  @Post('validate-url')
  validateUrl(@Body() body: FetchDto) {
    if (!body.url) {
      throw new HttpException('URL is required', HttpStatus.BAD_REQUEST);
    }

    const result = this.ssrfHttpService.validateUrl(body.url);
    return {
      url: body.url,
      ...result,
    };
  }

  /**
   * Verify webhook URL is safe and reachable
   */
  @Post('webhooks/verify')
  async verifyWebhook(@Body() body: WebhookVerifyDto) {
    if (!body.webhookUrl) {
      throw new HttpException('webhookUrl is required', HttpStatus.BAD_REQUEST);
    }

    // First validate URL
    const validation = this.ssrfHttpService.validateUrl(body.webhookUrl);
    if (!validation.valid) {
      throw new HttpException(
        {
          verified: false,
          error: 'Webhook URL rejected: internal/private endpoints not allowed',
          reason: validation.reason,
        },
        HttpStatus.FORBIDDEN,
      );
    }

    try {
      const response = await this.ssrfHttpService.post(
        body.webhookUrl,
        { test: true, timestamp: Date.now() },
        { timeout: 5000 },
      );

      return {
        verified: true,
        status: response.status,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        {
          verified: false,
          error: 'Webhook URL unreachable',
          message: error.message,
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
