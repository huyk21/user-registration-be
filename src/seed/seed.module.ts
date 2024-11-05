// src/seed/seed.module.ts
import { Module } from '@nestjs/common';
import { SeedService } from './seed.service';
import { DatabaseProvider } from '../database.provider';

@Module({
  providers: [SeedService, DatabaseProvider],
  exports: [SeedService],
})
export class SeedModule {}
