import { Controller, Post, Body, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerDto, loginDto } from './auth.dto';
@Controller('auth')
export class AuthController {

    constructor (
    private readonly authService: AuthService,
    ) {}
    @Post('register')
    async registerUser(@Body() registerDto: registerDto) {
      const { email, password, role } = registerDto;
      return this.authService.registerUser(email, password, role);
    }
  
    @Post('login')
    async loginUser(@Body() loginDto: loginDto) {
      const { email, password, role } = loginDto;
      return this.authService.loginUser(email, password, role);
    }

    @Post('update-password/:token')
    async updatePassword(
      @Param('token') token: string, 
      @Body('currentPassword') currentPassword: string,
      @Body('newPassword') newPassword: string,
    ) {
      return this.authService.updatePassword(token, currentPassword, newPassword);
    }
}
