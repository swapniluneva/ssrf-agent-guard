import { DynamicModule, Global, Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SsrfHttpService } from './ssrf-http.service';

export interface SsrfHttpModuleOptions {
  mode?: 'block' | 'report' | 'allow';
  blockCloudMetadata?: boolean;
  detectDnsRebinding?: boolean;
  metadataHosts?: string[];
  policy?: {
    allowDomains?: string[];
    denyDomains?: string[];
    denyTLD?: string[];
  };
}

export const SSRF_HTTP_OPTIONS = 'SSRF_HTTP_OPTIONS';

@Global()
@Module({})
export class SsrfHttpModule {
  static forRoot(options: SsrfHttpModuleOptions = {}): DynamicModule {
    return {
      module: SsrfHttpModule,
      imports: [HttpModule],
      providers: [
        {
          provide: SSRF_HTTP_OPTIONS,
          useValue: options,
        },
        SsrfHttpService,
      ],
      exports: [SsrfHttpService],
    };
  }

  static forRootAsync(options: {
    useFactory: (
      ...args: any[]
    ) => Promise<SsrfHttpModuleOptions> | SsrfHttpModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: SsrfHttpModule,
      imports: [HttpModule],
      providers: [
        {
          provide: SSRF_HTTP_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        SsrfHttpService,
      ],
      exports: [SsrfHttpService],
    };
  }
}
