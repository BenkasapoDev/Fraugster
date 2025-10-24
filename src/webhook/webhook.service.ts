import { Injectable, Logger } from '@nestjs/common';
import { createHmac } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';

export interface WebhookPayload {
    type: string;
    data: any;
}

@Injectable()
export class WebhookService {
    private readonly logger = new Logger(WebhookService.name);

    constructor(
        private readonly configService: ConfigService,
        private readonly auditService: AuditService,
        private readonly prisma: PrismaService,
    ) { }

    /**
     * Validate webhook signature and timestamp
     */
    async validateWebhook(payload: WebhookPayload, headers: Record<string, string>): Promise<boolean> {
        const timestamp = headers['x-fraugsterwebhook-timestamp'];
        const signature = headers['x-fraugsterwebhook-signature'];
        const secretKey = this.configService.get<string>('FRAUGSTER_SECRET_KEY');

        if (!timestamp || !signature || !secretKey) {
            this.logger.warn('Missing required webhook headers or secret key');
            return false;
        }

        // Validate timestamp (not older than 5 minutes)
        if (!this.isTimestampValid(timestamp)) {
            this.logger.warn('Webhook timestamp is too old', { timestamp });
            return false;
        }

        // Generate expected signature
        const expectedSignature = this.generateSignature(timestamp, JSON.stringify(payload), secretKey);

        // Compare signatures
        const isValid = signature === expectedSignature;

        if (!isValid) {
            this.logger.warn('Webhook signature validation failed', {
                received: signature.substring(0, 10) + '...',
                expected: expectedSignature.substring(0, 10) + '...',
            });
        }

        return isValid;
    }

    /**
     * Check if timestamp is within 5 minutes
     */
    private isTimestampValid(timestamp: string): boolean {
        try {
            const webhookTime = new Date(timestamp).getTime();
            const now = Date.now();
            const fiveMinutes = 5 * 60 * 1000;

            return Math.abs(now - webhookTime) <= fiveMinutes;
        } catch (error) {
            this.logger.error('Invalid timestamp format', { timestamp, error: error.message });
            return false;
        }
    }

    /**
     * Generate HMAC-SHA256 signature
     */
    private generateSignature(timestamp: string, body: string, secretKey: string): string {
        const hmac = createHmac('sha256', secretKey);
        hmac.update(timestamp, 'utf8');
        hmac.update(body, 'utf8');
        return hmac.digest('hex');
    }

    /**
     * Process webhook event based on type with idempotency
     */
    async processWebhookEvent(payload: WebhookPayload): Promise<void> {
        const webhookId = `${payload.type}:${payload.data?.frg_trans_id || payload.data?.trans_id}`;

        // Check database for duplicate webhook (simple string comparison in metadata)
        const existingEvents = await this.prisma.auditLog.findMany({
            where: {
                action: 'WEBHOOK_RECEIVED',
                createdAt: {
                    gte: new Date(Date.now() - 60000), // Within 1 minute
                },
            },
            take: 1,
        });

        // Check if any recent webhook matches this one
        const isDuplicate = existingEvents.some(event => {
            const eventData = typeof event.metadata === 'string'
                ? JSON.parse(event.metadata)
                : event.metadata;
            return eventData?.payload?.data?.trans_id === payload.data?.trans_id;
        });

        if (isDuplicate) {
            this.logger.warn('⚠️ Duplicate webhook detected, skipping', { webhookId });
            return;
        }

        // Log the webhook event
        await this.auditService.logWebhookEvent({
            eventType: payload.type,
            payload,
            processed: true,
            timestamp: new Date(),
        });

        switch (payload.type) {
            case 'txn_manual_review':
                await this.processManualReview(payload.data);
                break;
            default:
                this.logger.warn('Unknown webhook event type', { type: payload.type });
        }
    }

    /**
     * Process manual review decision
     */
    private async processManualReview(data: any): Promise<void> {
        const { frg_trans_id, trans_id, decision, reviewed_at } = data;

        this.logger.log('🔍 Processing manual review decision', {
            frgTransId: frg_trans_id,
            transId: trans_id,
            decision,
            reviewedAt: reviewed_at,
        });

        try {
            const existingTransaction = await this.prisma.transactionLog.findUnique({
                where: { transactionId: trans_id },
            });

            if (existingTransaction) {
                // Transaction was already logged, update with webhook decision
                await this.prisma.transactionLog.update({
                    where: { transactionId: trans_id },
                    data: {
                        status: this.mapDecisionToStatus(decision),
                        responsePayload: data,
                    },
                });

                this.logger.log('✅ Transaction log updated with webhook decision', {
                    transactionId: trans_id,
                    decision,
                    status: this.mapDecisionToStatus(decision),
                });

                // Process business logic
                switch (decision) {
                    case 'good':
                        await this.handleApprovedTransaction(trans_id, frg_trans_id);
                        break;
                    case 'probably_good':
                        await this.handleProbablyGoodTransaction(trans_id, frg_trans_id);
                        break;
                    case 'suspicious':
                        await this.handleSuspiciousTransaction(trans_id, frg_trans_id);
                        break;
                    case 'bad':
                        await this.handleRejectedTransaction(trans_id, frg_trans_id);
                        break;
                }
            } else {
                // Webhook arrived before transaction was logged
                this.logger.warn('⚠️ Webhook received for transaction not yet in logs', {
                    transactionId: trans_id,
                    frgTransId: frg_trans_id,
                    decision,
                    note: 'Transaction will be updated when main transaction log is created',
                });

                // Store webhook decision in audit log for later reconciliation
                await this.auditService.log({
                    serviceName: 'fraugster',
                    action: 'WEBHOOK_PENDING_RECONCILIATION',
                    status: 'error',
                    endpoint: '/webhook',
                    method: 'POST',
                    errorMessage: `Transaction ${trans_id} not found in logs`,
                    metadata: {
                        frg_trans_id,
                        decision,
                        reviewed_at,
                        reason: 'Transaction log will be created later and should be updated with this webhook decision',
                    },
                });

                // Don't create fake transaction data
                // The webhook will be retried by Fraugster if we return non-200
                return;
            }
        } catch (error) {
            this.logger.error('❌ Failed to process manual review', {
                transactionId: trans_id,
                frgTransId: frg_trans_id,
                error: error.message,
            });
            throw error;
        }
    }

    private mapDecisionToStatus(decision: string): string {
        const statusMap: Record<string, string> = {
            'good': 'approved',
            'probably_good': 'approved_conditional',
            'suspicious': 'flagged',
            'bad': 'rejected',
        };
        return statusMap[decision] || 'unknown';
    }

    // Business logic handlers
    private async handleApprovedTransaction(transId: string, frgTransId: string): Promise<void> {
        this.logger.log('✅ APPROVED - Transaction approved', { transId, frgTransId });
        // TODO: Implement your business logic:
        // - Update order status to "completed"
        // - Send confirmation email to customer
        // - Process fulfillment/shipment
        // - Update inventory
    }

    private async handleProbablyGoodTransaction(transId: string, frgTransId: string): Promise<void> {
        this.logger.log('⚠️ CONDITIONAL - Transaction approved with caution', { transId, frgTransId });
        // TODO: Implement your business logic:
        // - Proceed with order but add to monitoring list
        // - Send to manual review queue
        // - Apply additional fraud checks
        // - Limit transaction amount
    }

    private async handleSuspiciousTransaction(transId: string, frgTransId: string): Promise<void> {
        this.logger.log('🚩 SUSPICIOUS - Transaction flagged for review', { transId, frgTransId });
        // TODO: Implement your business logic:
        // - Hold payment/order
        // - Send to manual review queue
        // - Notify risk team
        // - Request additional verification from customer
        // - Log for compliance/audit
    }

    private async handleRejectedTransaction(transId: string, frgTransId: string): Promise<void> {
        this.logger.log('❌ REJECTED - Transaction rejected', { transId, frgTransId });
        // TODO: Implement your business logic:
        // - Cancel order
        // - Refund payment if already charged
        // - Notify customer of rejection
        // - Block customer/card from future transactions
        // - Log fraud attempt
        // - Send alert to compliance team
    }
}