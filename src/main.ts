import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT ?? 3000;
  // Bind to 0.0.0.0 for Render deployment, localhost for local development
  const host = process.env.NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';

  await app.listen(port, host);
  console.log(`Application is running on: http://${host}:${port}`);
}
bootstrap();
