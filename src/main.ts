import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

declare const module: any;

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: ['https://unspalsh-gallery-lrf9rpdi9-huys-projects-b0a5a2b0.vercel.app/'], // Replace with your frontend URL
    methods: 'GET,POST,PUT,DELETE', // Specify allowed methods
    credentials: true, // Enable if you need to send cookies
  });
  

  await app.listen(process.env.PORT ?? 3000);
  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => app.close());
  }
}
bootstrap();
