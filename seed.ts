// seed.ts
import { NestFactory } from '@nestjs/core';
import { SeedModule } from './src/seed/seed.module';
import { SeedService } from './src/seed/seed.service';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(SeedModule);
  const seedService = app.get(SeedService);

  await seedService.seedUsers(); // Run the seeding method

  await app.close(); // Close the app context after seeding
}

bootstrap().catch((err) => {
  console.error('Seeding error:', err);
});
