import { Controller, Post, Param, Body, HttpException, HttpStatus, Put, UseGuards, SetMetadata } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt'; // Ensure JwtService is imported
import { ProfileService } from './profile.service'; // Ensure ProfileService is correctly imported
import { CreateProfileDto } from './create-profile.dto';
import { RolesGuard } from 'src/guards/roles.guards';
import { Role } from 'src/guards/role.enum';

@Controller('profile')
export class ProfileController {
  constructor(
    private readonly profileService: ProfileService,
    private readonly jwt: JwtService, // Inject JwtService for token decoding
  ) {}

  @Post('/create-profile/:token')
  @UseGuards(RolesGuard)
  @SetMetadata('roles', [Role.USER]) 
  async createProfile(
    @Param('token') token: string, // Token passed as a route parameter
    @Body() profileData:CreateProfileDto,
  ) {
    try {
      // Decode the token to extract the user ID
      const decoded = this.jwt.verify(token, { secret: process.env.JWT_SECRET }); // Use your JWT_SECRET
      if (!decoded || !decoded.id) {
        throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
      }

      const userId = decoded.id; // Extract the user ID from the token
      return await this.profileService.createProfile(userId, profileData);
    } catch (error) {
      throw new HttpException(
        error.message || 'Failed to create profile',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  
  @Put('/update-profile/:token')
  async updateProfile (
    @Param('token') token: string, // Token passed as a route parameter
    @Body() profileData:CreateProfileDto,
  ) {
    try {
      // Decode the token to extract the user ID
      const decoded = this.jwt.verify(token, { secret: process.env.JWT_SECRET }); // Use your JWT_SECRET
      if (!decoded || !decoded.id) {
        throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
      }

      const userId = decoded.id; // Extract the user ID from the token
      return await this.profileService.updateProfile(userId, profileData);
    } catch (error) {
      throw new HttpException(
        error.message || 'Failed to create profile',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

}
