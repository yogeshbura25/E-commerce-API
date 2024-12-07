import { IsString, IsOptional, IsInt } from 'class-validator';

export class CreateProfileDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  State?: string;

  @IsOptional()
  @IsInt()
  phone_number?: number;

  @IsOptional()
  @IsInt()
  pin_code?: number;
}
