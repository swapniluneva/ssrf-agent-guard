import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`NestJS server running on port ${port}`);
  console.log('\nTest endpoints:');
  console.log('  POST /fetch          - Fetch any URL (SSRF protected)');
  console.log('  POST /fetch-trusted  - Fetch from allowlisted URLs only');
  console.log('  POST /validate-url   - Validate URL without fetching');
  console.log('  POST /webhooks/verify - Verify webhook URL');
  console.log('\nExample requests:');
  console.log(
    '  curl -X POST http://localhost:3000/fetch -H "Content-Type: application/json" -d \'{"url":"https://httpbin.org/get"}\'',
  );
}

bootstrap();
