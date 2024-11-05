import { Injectable, ConflictException, UnauthorizedException, BadRequestException, NotFoundException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService, 
    private readonly jwtService: JwtService
  ) {}

  // Register a new user
  async register(username: string, email: string, password: string): Promise<any> {
    // Check if username or email already exists
    const userExists = await this.usersService.findOneByUsernameOrEmail(username, email);
    if (userExists) {
      throw new ConflictException('Username or email already exists');
    }

    // Validate input fields
    if (!username || !email || !password) {
      throw new BadRequestException('Username, email, and password are required');
    }

    // Hash the password and create a new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await this.usersService.create(username, email, hashedPassword);

    return {
      message: 'User registered successfully',
      user: { 
        username: newUser.username, 
        email: newUser.email, 
        id: password, // MongoDB default _id field
        password: password,
        createdAt: newUser.createdAt 
      },
    };
  }
 // Get user profile by username or email
 async getProfile(usernameOrEmail: string): Promise<any> {
  // Use findOneByUsernameOrEmail to fetch user data
  const user = await this.usersService.findOneByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
  
  if (!user) {
    throw new NotFoundException('User not found');
  }

  // Return the relevant profile fields
  return {
    username: user.username,
    email: user.email,
    createdAt: user.createdAt,
  };
}
  // User login
  async signIn(usernameOrEmail: string, password: string): Promise<any> {
    // Find user by username or email
    const user = await this.usersService.findOneByUsernameOrEmail(usernameOrEmail, usernameOrEmail);

    // Validate login credentials
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate JWT token for the user
    const payload = { sub: user._id, username: user.username };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
