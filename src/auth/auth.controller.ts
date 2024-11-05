import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseGuards
} from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
@Controller('user')
export class AuthController {
  constructor(private authService: AuthService,
    private readonly usersService: UsersService, 
  ) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() signInDto: Record<string, any>) {
    // Allow login with either username or email
    return this.authService.signIn(signInDto.usernameOrEmail, signInDto.password);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('register')
  register(@Body() registerDto: Record<string, any>) {
    // Register with username, email, and password
    return this.authService.register(registerDto.username, registerDto.email, registerDto.password);
  }

  @UseGuards(AuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    
    const userProfile = await this.usersService.findOneByUsernameOrEmail(req.user.username, req.user.username); // Fetch full profile from DB
    return userProfile;
  }
}
