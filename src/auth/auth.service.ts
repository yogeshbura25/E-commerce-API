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
      if (error instanceof HttpException) {
        throw error;
      } else {
        throw new HttpException(
          'Internal Server Error',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
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
        expiresIn: '10M',
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
      if (error instanceof HttpException) {
        throw error;
      }

      console.error('Error during user login:', error.message || error);
      throw new HttpException(
        'Internal Server Error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async updatePassword(
    token: string,
    currentPassword: string,
    newPassword: string,
  ) {
    try {
      // Decode the JWT token
      const decodedToken = this.jwt.decode(token) as any;

      if (!decodedToken) {
        throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
      }

      const { id } = decodedToken; // Extract email from decoded token

      // Find the user by email
      const user = await this.prisma.user.findUnique({
        where: { id },
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Compare current password with the stored password
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

      // Update the user's password
      await this.prisma.user.update({
        where: { id },
        data: { password: hashedNewPassword },
      });

      return { message: 'Password updated successfully' };
    } catch (error) {
      throw new HttpException(
        error.message || 'Internal server error',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
