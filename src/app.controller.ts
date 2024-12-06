import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { RolesGuard } from './guards/roles.guards';
import { SetMetadata } from '@nestjs/common';
import { Role } from './guards/role.enum'; 

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @UseGuards(RolesGuard)
  @SetMetadata('roles', [Role.ADMIN]) 
  getHello(): string {
    return this.appService.getHello();
  }
}
