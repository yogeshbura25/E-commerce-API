import { Controller, Post, Body, Param, HttpException, HttpStatus, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerDto, loginDto } from './auth.dto';
import { JwtService } from '@nestjs/jwt';
@Controller('auth')
export class AuthController {

    constructor (
    private readonly authService: AuthService,
    private readonly jwt: JwtService
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
      @Param('token') token: string, // Extract token from the route
      @Body('currentPassword') currentPassword: string,
      @Body('newPassword') newPassword: string,
    ) {
      try {
        // Decode and validate the token in the controller
        const decodedToken = this.jwt.verify(token, { secret: process.env.JWT_SECRET });
  
        if (!decodedToken || !decodedToken.id) {
          throw new HttpException('Invalid or expired token', HttpStatus.UNAUTHORIZED);
        }
  
        const userId = decodedToken.id; // Extract the user ID from the token
  
        // Pass the userId, currentPassword, and newPassword to the service
        return this.authService.updatePassword(userId, currentPassword, newPassword);
      } catch (error) {
        console.error('Error decoding token in controller:', error.message);
        throw new HttpException(
          error.message || 'Failed to update password',
          error.status || HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
    }

    @Delete('delete-profile')
    async deleteDetails(@Body() { email }: { email: string }){
      return this.authService.deleteDetails(email)
    }
}
