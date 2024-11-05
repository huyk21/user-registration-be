// src/users/users.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User, UserDocument } from './users.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>
  ) {}

  // Find user by username or email
  async findOneByUsernameOrEmail(
    username: string,
    email: string
  ): Promise<UserDocument | undefined> {
    return this.userModel.findOne({
      $or: [{ username }, { email }],
    }).exec();
  }

  // Create a new user
  async create(username: string, email: string, password: string): Promise<UserDocument> {
    // Check if username or email already exists
    const existingUser = await this.findOneByUsernameOrEmail(username, email);
    if (existingUser) {
      throw new BadRequestException('Username or email already exists');
    }

    // Validate input
    if (!username || !email || !password) {
      throw new BadRequestException('Username, email, and password are required');
    }

    
    const newUser = new this.userModel({
      username,
      email,
      password: password,
      createdAt: new Date(),
      
    });

    return newUser.save(); // Save the new user document to MongoDB
  }
}
