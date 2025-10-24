import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WebhookController } from './webhook.controller';
import { WebhookService } from './webhook.service';
import { AuditModule } from '../audit/audit.module';

@Module({
    imports: [
        ConfigModule,  // ✅ Import ConfigModule for ConfigService
        AuditModule,   // ✅ Import AuditModule for AuditService
    ],
    controllers: [WebhookController],
    providers: [WebhookService],
    exports: [WebhookService],
})
export class WebhookModule { }