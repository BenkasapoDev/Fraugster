import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AuthController } from './auth/auth.controller';
import { TransactionController } from './transaction/transaction.controller';
import { AppService } from './app.service';
import { AuthService } from './auth/auth.service';
import { TransactionService } from './transaction/transaction.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    HttpModule,
    PrismaModule,
    AuditModule,
  ],
  controllers: [AppController, AuthController, TransactionController],
  providers: [AppService, AuthService, TransactionService],
})
export class AppModule { }
