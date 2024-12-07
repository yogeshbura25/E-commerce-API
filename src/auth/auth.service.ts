import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async registerUser(email: string, password: string, role: string) {
    try {
      const finduser = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (finduser) {
        throw new HttpException(
          'user email already exists',
          HttpStatus.CONFLICT,
        );
      }

      if (role && role !== 'USER' && role !== 'ADMIN') {
        throw new HttpException(
          'Invalid role. Role must be either USER or ADMIN.',
          HttpStatus.BAD_REQUEST,
        );
      }

      const hashedpassword = await bcrypt.hash(password, 6);

      const createuser = await this.prisma.user.create({
        data: {
          email,
          password: hashedpassword,
          role: role || 'USER', // Default role is 'USER' if not provided
        },
      });

      return {
        success: true,
        statusCode: HttpStatus.CREATED,
        message: 'New user Successfully Added',
        data: createuser,
      };
    } catch (error) {
        throw new HttpException(
            error.message || 'Internal server error',
            error.status || HttpStatus.INTERNAL_SERVER_ERROR,
          );
    }
  }

  async loginUser(email: string, password: string, role: string) {
    try {
      const findUser = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!findUser) {
        throw new HttpException('User does not exist', HttpStatus.NOT_FOUND);
      }

      if (findUser.role !== role) {
        throw new HttpException(
          'User role does not match, please try again',
          HttpStatus.FORBIDDEN,
        );
      }

      const isPasswordValid = await bcrypt.compare(password, findUser.password);
      if (!isPasswordValid) {
        throw new HttpException(
          'Invalid password, please try again',
          HttpStatus.UNAUTHORIZED,
        );
      }

      const payload = { id: findUser.id, role: findUser.role };

      const token = this.jwt.sign(payload, {
        secret: process.env.JWT_SECRET,
        expiresIn: '10h',
      });

      return {
        success: true,
        statusCode: HttpStatus.OK,
        message: 'Login successful',
        data: {
          token,
        },
      };
    } catch (error) {
        throw new HttpException(
            error.message || 'Internal server error',
            error.status || HttpStatus.INTERNAL_SERVER_ERROR,
          );
    }
  }

  async updatePassword(
    userId: number, // Accept userId directly
    currentPassword: string,
    newPassword: string,
  ) {
    try {
      // Find the user by ID
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Compare the current password with the stored password
      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );

      if (!isCurrentPasswordValid) {
        throw new HttpException(
          'Current password is incorrect',
          HttpStatus.BAD_REQUEST,
        );
      }

      // Hash the new password
      const hashedNewPassword = await bcrypt.hash(newPassword, 6);

      // Update the user's password in the database
      await this.prisma.user.update({
        where: { id: userId },
        data: { password: hashedNewPassword },
      });

      return { message: 'Password updated successfully' };
    } catch (error) {
      console.error('Error in updatePassword service:', error.message);
      throw new HttpException(
        error.message || 'Internal server error',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async deleteDetails(email: string) {
    try {
      // Find the user by email
      const user = await this.prisma.user.findUnique({
        where: { email },
      });
  
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
  
      // Delete the associated profile first (if it exists)
      await this.prisma.profile.deleteMany({
        where: { userId: user.id }, // Delete profile(s) linked to the user
      });
  
      // Delete the user after deleting the profile
       await this.prisma.user.delete({
        where: { email },
      });
  
      return {
        success: true,
        message: 'User and associated profile deleted successfully',
     
      };
    } catch (error) {
      console.error('Error deleting user and profile:', error.message);
      throw new HttpException(
        error.message || 'Failed to delete user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  
}
