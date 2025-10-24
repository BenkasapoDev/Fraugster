import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';

@Module({
    imports: [
        HttpModule,     // ✅ For HttpService (making API requests)
        ConfigModule,   // ✅ For ConfigService (environment variables)
        PrismaModule,   // ✅ For PrismaService
        AuditModule,    // ✅ For AuditService
    ],
    controllers: [AuthController],
    providers: [AuthService],
    exports: [AuthService],
})
export class AuthModule { }