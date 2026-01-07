import { Module } from '@nestjs/common';
import { SsrfHttpModule } from './ssrf-http/ssrf-http.module';
import { FetchModule } from './fetch/fetch.module';

@Module({
  imports: [
    SsrfHttpModule.forRoot({
      mode: 'block',
      blockCloudMetadata: true,
      detectDnsRebinding: true,
      policy: {
        denyDomains: ['*.internal.local'],
        denyTLD: ['local', 'internal', 'localhost'],
      },
    }),
    FetchModule,
  ],
})
export class AppModule {}
