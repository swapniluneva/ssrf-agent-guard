import { Injectable, Inject, Logger, HttpException, HttpStatus, Optional } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { AxiosRequestConfig, AxiosResponse } from 'axios';
import { firstValueFrom } from 'rxjs';
import { SSRF_HTTP_OPTIONS, SsrfHttpModuleOptions } from './ssrf-http.module';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const ssrfAgentGuard = require('ssrf-agent-guard');

// Cloud metadata IPs to block
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', '169.254.169.253', '168.63.129.16',
  '169.254.170.2', '100.100.100.200', '169.254.0.0'
]);

@Injectable()
export class SsrfHttpService {
  private readonly logger = new Logger(SsrfHttpService.name);
  private readonly options: SsrfHttpModuleOptions;

  constructor(
    private readonly httpService: HttpService,
    @Optional() @Inject(SSRF_HTTP_OPTIONS) options?: SsrfHttpModuleOptions,
  ) {
    this.options = options || {};
  }

  /**
   * Check if an error is from SSRF protection
   */
  private isSsrfError(error: any): boolean {
    const msg = error.message || '';
    return msg.includes('is not allowed') ||
           msg.includes('is denied') ||
           msg.includes('rebinding');
  }

  /**
   * Make an SSRF-protected GET request
   */
  async get<T = any>(
    url: string,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'GET', url });
  }

  /**
   * Make an SSRF-protected POST request
   */
  async post<T = any>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'POST', url, data });
  }

  /**
   * Make an SSRF-protected request with custom options
   */
  async request<T = any>(config: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    const url = config.url;

    if (!url) {
      throw new HttpException('URL is required', HttpStatus.BAD_REQUEST);
    }

    try {
      // Create protected agent
      const agent = ssrfAgentGuard(url, {
        ...this.options,
        logger: (level, msg, meta) => {
          if (level === 'error') {
            this.logger.error(msg, meta);
          } else if (level === 'warn') {
            this.logger.warn(msg, meta);
          } else {
            this.logger.log(msg, meta);
          }
        },
      });

      // Make request with protected agent
      const response = await firstValueFrom(
        this.httpService.request<T>({
          ...config,
          httpAgent: agent,
          httpsAgent: agent,
        }),
      );

      return response;
    } catch (error) {
      if (this.isSsrfError(error)) {
        this.logger.warn(`SSRF attempt blocked: ${url}`);
        throw new HttpException(
          {
            error: 'Request blocked',
            reason: 'SSRF protection: The requested URL is not allowed',
          },
          HttpStatus.FORBIDDEN,
        );
      }

      throw error;
    }
  }

  /**
   * Make a request with custom SSRF policy (overrides module defaults)
   */
  async requestWithPolicy<T = any>(
    config: AxiosRequestConfig,
    policy: SsrfHttpModuleOptions,
  ): Promise<AxiosResponse<T>> {
    const url = config.url;

    if (!url) {
      throw new HttpException('URL is required', HttpStatus.BAD_REQUEST);
    }

    try {
      const mergedOptions = { ...this.options, ...policy };
      const agent = ssrfAgentGuard(url, {
        ...mergedOptions,
        logger: (level, msg, meta) => {
          if (level === 'error') {
            this.logger.error(msg, meta);
          } else if (level === 'warn') {
            this.logger.warn(msg, meta);
          } else {
            this.logger.log(msg, meta);
          }
        },
      });

      const response = await firstValueFrom(
        this.httpService.request<T>({
          ...config,
          httpAgent: agent,
          httpsAgent: agent,
        }),
      );

      return response;
    } catch (error) {
      if (this.isSsrfError(error)) {
        this.logger.warn(`SSRF attempt blocked: ${url}`);
        throw new HttpException(
          {
            error: 'Request blocked',
            reason: 'SSRF protection: The requested URL is not allowed',
          },
          HttpStatus.FORBIDDEN,
        );
      }

      throw error;
    }
  }

  /**
   * Validate a URL without making a request
   */
  validateUrl(urlString: string, customPolicy?: SsrfHttpModuleOptions): { valid: boolean; reason?: string } {
    try {
      const url = new URL(urlString);
      const hostname = url.hostname;
      const options = customPolicy ? { ...this.options, ...customPolicy } : this.options;

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
      return { valid: false, reason: error.message };
    }
  }
}
