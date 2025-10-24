import { Injectable, Logger } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class TransactionService {
    private readonly logger = new Logger(TransactionService.name);

    constructor(
        private readonly authService: AuthService,
        private readonly prisma: PrismaService,
        private readonly auditService: AuditService,
    ) { }

    /**
     * Send a transaction to Fraugster API with logging
     */
    async sendTransaction(transactionData: any): Promise<any> {
        const startTime = Date.now();

        try {
            // Log the transaction attempt
            await this.prisma.transactionLog.create({
                data: {
                    transactionId: transactionData.trans_id,
                    platformId: transactionData.platform_id || 'unknown',
                    orderId: transactionData.order_id || transactionData.trans_id,
                    amount: transactionData.trans_amt || 0,
                    currency: transactionData.trans_currency || 'USD',
                    paymentMethod: transactionData.pmt_method || 'card',
                    customerEmail: transactionData.cust_email || '',
                    status: 'sending',
                    requestPayload: transactionData,
                },
            });

            // Send to Fraugster
            const result = await this.authService.makeAuthenticatedRequest(
                '/api/v2/transaction',
                'POST',
                transactionData,
            );

            const duration = Date.now() - startTime;

            // Update transaction log with success
            await this.prisma.transactionLog.update({
                where: { transactionId: transactionData.trans_id },
                data: {
                    status: 'sent',
                    responsePayload: result,
                },
            });

            // Audit log
            await this.auditService.logTransaction({
                transactionId: transactionData.trans_id,
                action: 'TRANSACTION_SENT',
                status: 'SUCCESS',
                duration,
                metadata: { result },
            });

            this.logger.log(`Transaction sent successfully`, {
                transactionId: transactionData.trans_id,
                duration: `${duration}ms`,
            });

            return result;

        } catch (error) {
            const duration = Date.now() - startTime;

            // Update transaction log with error
            await this.prisma.transactionLog.update({
                where: { transactionId: transactionData.trans_id },
                data: {
                    status: 'failed',
                    errorMessage: error.message,
                },
            }).catch(updateError => {
                this.logger.warn('Failed to update transaction log with error', updateError);
            });

            // Audit log the failure
            await this.auditService.logTransaction({
                transactionId: transactionData.trans_id,
                action: 'TRANSACTION_FAILED',
                status: 'FAILED',
                duration,
                errorMessage: error.message,
            });

            throw error;
        }
    }

    /**
     * Example: Get transaction status
     */
    async getTransactionStatus(transactionId: string): Promise<any> {
        return this.authService.makeAuthenticatedRequest(
            `/api/v2/transactions/${transactionId}`,
            'GET',
        );
    }

    /**
     * Add more Fraugster API methods here as needed
     */
}
