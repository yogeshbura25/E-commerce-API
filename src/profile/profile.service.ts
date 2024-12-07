import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { CreateProfileDto } from './create-profile.dto';

@Injectable()
export class ProfileService {
  constructor(private prisma: PrismaService) {}

  async createProfile(userId: number, profileData: CreateProfileDto) {
    try {
      // Fetch the user details by userId from the token
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Check if the user already has a profile
      const existingProfile = await this.prisma.profile.findUnique({
        where: { userId }, // Check for existing profile by userId
      });

      if (existingProfile) {
        throw new HttpException(
          'User Profile Details already exists for this user',
          HttpStatus.CONFLICT,
        );
      }

      // Create the profile linked to the user
      const profile = await this.prisma.profile.create({
        data: {
          userId: user.id, // Ensure profile is linked to the user
          ...profileData, // Include profile data from the request body
        },
        include: {
          user: true, // Include user details in the response
        },
      });

      // Return both profile and user details
      return {
        success: true,
        message: 'Profile created successfully',
        profile,
      };
    } catch (error) {
      console.error('Error creating profile:', error.message); // Log the error
      throw new HttpException(
        error.message || 'Profile creation failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async updateProfile(userId: number, profileData: CreateProfileDto) {
    try {
      const existingProfile = await this.prisma.profile.findUnique({
        where: {
          userId,
        },
      });

      if (!existingProfile) {
        throw new HttpException(
          'Profile not found for this user',
          HttpStatus.NOT_FOUND,
        );
      }

      const updatedProfile = await this.prisma.profile.update({
        where: { userId },
        data: {
          // Update only the fields that are provided (optional)
          name: profileData.name ?? existingProfile.name, // Use existing name if not provided
          phone_number:
          profileData.phone_number ?? existingProfile.phone_number,
          address: profileData.address ?? existingProfile.address,
          State: profileData.State ?? existingProfile.State,
          pin_code: profileData.pin_code ?? existingProfile.pin_code,
        },
      });

      return {
        success: true,
        message: 'Profile updated successfully',
        updatedProfile,
      };
    } catch (error) {
      throw new HttpException(
        error.message || 'Profile creation failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
