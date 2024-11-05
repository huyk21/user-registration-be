// src/seed/seed.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { DatabaseProvider } from '../database.provider';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  constructor(private readonly dbProvider: DatabaseProvider) {}

  async seedUsers() {
    this.logger.log('Starting user data seeding...');

    // Ensure database connection
    const db = await this.dbProvider.connect();
    const usersCollection = db.collection('users');

    // Sample users to seed
    const hashedPassword = await bcrypt.hash('password123', 10);
    const users = [
      { username: 'john', email: 'john@example.com', password: hashedPassword },
      { username: 'maria', email: 'maria@example.com', password: hashedPassword },
    ];

    for (const user of users) {
      const existingUser = await usersCollection.findOne({ email: user.email });
      if (!existingUser) {
        await usersCollection.insertOne(user);
        this.logger.log(`User ${user.username} seeded.`);
      } else {
        this.logger.log(`User ${user.username} already exists. Skipping.`);
      }
    }

    this.logger.log('User data seeding completed.');
  }
}
