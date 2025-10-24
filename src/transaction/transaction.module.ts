import { Module } from '@nestjs/common';
import { TransactionController } from './transaction.controller';
import { TransactionService } from './transaction.service';

import { PrismaModule } from '../prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from 'src/auth/auth.module';

@Module({
    imports: [
        AuthModule,     // ✅ For AuthService
        PrismaModule,   // ✅ For PrismaService
        AuditModule,    // ✅ For AuditService
    ],
    controllers: [TransactionController],
    providers: [TransactionService],
    exports: [TransactionService],
})
export class TransactionModule { }