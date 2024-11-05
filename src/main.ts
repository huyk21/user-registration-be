import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

declare const module: any;

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: '*', // Allows requests from any origin
    methods: 'GET,POST,PUT,DELETE,OPTIONS', // Allows common HTTP methods (OPTIONS is included for preflight requests)
    credentials: true, // Include if you need to allow cookies
  });
  

  await app.listen(process.env.PORT ?? 3000);
  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => app.close());
  }
}
bootstrap();
