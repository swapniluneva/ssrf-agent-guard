# NestJS SSRF Protection Example

This example demonstrates how to use `ssrf-agent-guard` with NestJS to protect your application from SSRF attacks.

## Setup

```bash
cd examples/nestjs
npm install
npm run build
npm start
```

## Endpoints

### POST /fetch
Fetches an external URL with SSRF protection.

```bash
# Safe request - allowed
curl -X POST http://localhost:3000/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"https://httpbin.org/get"}'

# SSRF attempt - blocked
curl -X POST http://localhost:3000/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

### POST /validate-url
Validates a URL without making a request.

```bash
curl -X POST http://localhost:3000/validate-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.1.1/"}'
```

### POST /fetch-trusted
Fetches from allowlisted domains only.

```bash
curl -X POST http://localhost:3000/fetch-trusted \
  -H "Content-Type: application/json" \
  -d '{"url":"https://api.github.com/users/octocat"}'
```

### POST /webhooks/verify
Verifies a webhook URL is safe and reachable.

```bash
curl -X POST http://localhost:3000/webhooks/verify \
  -H "Content-Type: application/json" \
  -d '{"webhookUrl":"https://webhook.site/your-id"}'
```

## Project Structure

```
src/
├── main.ts                        # Application entry point
├── app.module.ts                  # Root module with SsrfHttpModule config
├── ssrf-http/
│   ├── ssrf-http.module.ts        # Dynamic module for SSRF protection
│   ├── ssrf-http.service.ts       # Injectable HTTP service
│   └── index.ts
└── fetch/
    ├── fetch.controller.ts        # Example controller
    └── fetch.module.ts
```

## Key Patterns

### Module Configuration

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { SsrfHttpModule } from './ssrf-http/ssrf-http.module';

@Module({
  imports: [
    SsrfHttpModule.forRoot({
      mode: 'block',
      blockCloudMetadata: true,
      detectDnsRebinding: true,
      policy: {
        denyDomains: ['*.internal.local'],
        denyTLD: ['local', 'internal'],
      },
    }),
  ],
})
export class AppModule {}
```

### Async Configuration

```typescript
SsrfHttpModule.forRootAsync({
  useFactory: (configService: ConfigService) => ({
    mode: configService.get('SSRF_MODE') || 'block',
    policy: {
      allowDomains: configService.get('ALLOWED_DOMAINS')?.split(','),
    },
  }),
  inject: [ConfigService],
}),
```

### Using the Service

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { SsrfHttpService } from './ssrf-http/ssrf-http.service';

@Controller()
export class MyController {
  constructor(private readonly ssrfHttpService: SsrfHttpService) {}

  @Post('fetch')
  async fetch(@Body() body: { url: string }) {
    // Automatically protected against SSRF
    const response = await this.ssrfHttpService.get(body.url);
    return response.data;
  }
}
```

### Custom Policy Per Request

```typescript
const response = await this.ssrfHttpService.requestWithPolicy(
  { url, method: 'GET' },
  {
    policy: {
      allowDomains: ['api.trusted.com'],
    },
  },
);
```

### URL Validation Without Request

```typescript
const result = this.ssrfHttpService.validateUrl(url);
if (!result.valid) {
  throw new HttpException(result.reason, HttpStatus.FORBIDDEN);
}
```

## Using in Your Own Project

Copy the `src/ssrf-http/` directory to your NestJS project and import `SsrfHttpModule` in your root module.
