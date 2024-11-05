import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { UsersModule } from './users/users.module';
import { DatabaseProvider } from './database.provider';
import { SeedModule } from './seed/seed.module';
import { MongooseModule } from '@nestjs/mongoose';
@Module({
  imports: [MongooseModule.forRoot(process.env.DB_URL),SeedModule, AuthModule, UsersModule, ConfigModule.forRoot({
    isGlobal: true, // Makes the configuration available globally
  }),],
  controllers: [AppController],
  providers: [AppService, DatabaseProvider]
})
export class AppModule {}
