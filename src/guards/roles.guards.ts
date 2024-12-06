import { Injectable, CanActivate, ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request as ExpressRequest } from 'express';

export interface Request extends ExpressRequest {
  user?: any;
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());

    if (!requiredRoles) {
      return true;
    }

    const request: Request = context.switchToHttp().getRequest();
    const authorizationHeader = request.headers['authorization'];

    if (!authorizationHeader) {
      throw new UnauthorizedException('Authorization token is missing');
    }

    const bearerToken = authorizationHeader.split(' ')[1];

    if (!bearerToken) {
      throw new UnauthorizedException('Bearer token is missing');
    }

    try {
      const decoded = await this.jwtService.verifyAsync(bearerToken, {
        secret: process.env.JWT_SECRET,
      });
      request.user = decoded;

      const userRole = decoded.role;
      const userId = decoded.id;  

      if (!requiredRoles.includes(userRole)) {
        throw new ForbiddenException('You do not have permission to access this resource');
      }

      if (request.params.id && request.params.id !== userId) {
        throw new ForbiddenException('You are not allowed to access this resource');
      }

      return true;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Token has expired, please login again');
      } else if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid token, please login again');
      }
      throw new UnauthorizedException('Authorization failed, please try again');
    }
  }
}
