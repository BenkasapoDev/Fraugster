import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { createChildLogger } from '../logger/winston.logger';

export interface AuditLogData {
    serviceName: string;
    action: string;
    status: 'success' | 'failed' | 'error';
    statusCode?: number;
    endpoint?: string;
    method?: string;
    userId?: string;
    ipAddress?: string;
    userAgent?: string;
    requestId?: string;
    duration?: number;
    errorMessage?: string;
    metadata?: any;
}

@Injectable()
export class AuditService {
    private readonly logger = createChildLogger('AuditService');

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Log an audit event to the database
     */
    async log(data: AuditLogData): Promise<void> {
        try {
            await this.prisma.auditLog.create({
                data: {
                    serviceName: data.serviceName,
                    action: data.action,
                    status: data.status,
                    statusCode: data.statusCode,
                    endpoint: data.endpoint,
                    method: data.method,
                    userId: data.userId,
                    ipAddress: data.ipAddress,
                    userAgent: data.userAgent,
                    requestId: data.requestId,
                    duration: data.duration,
                    errorMessage: data.errorMessage,
                    metadata: data.metadata,
                },
            });

            this.logger.debug('📝 Audit log created', {
                action: data.action,
                status: data.status,
            });
        } catch (error) {
            // Don't throw - logging should never break the app
            this.logger.error('❌ Failed to create audit log', {
                error: error?.message,
                data,
            });
        }
    }

    /**
     * Log successful authentication
     */
    async logAuthentication(data: {
        requestId: string;
        duration: number;
        metadata?: any;
    }): Promise<void> {
        await this.log({
            serviceName: 'fraugster',
            action: 'authenticate',
            status: 'success',
            statusCode: 200,
            requestId: data.requestId,
            duration: data.duration,
            metadata: data.metadata,
        });
    }

    /**
     * Log failed authentication
     */
    async logAuthenticationFailure(data: {
        requestId: string;
        statusCode: number;
        errorMessage: string;
        metadata?: any;
    }): Promise<void> {
        await this.log({
            serviceName: 'fraugster',
            action: 'authenticate',
            status: 'failed',
            statusCode: data.statusCode,
            requestId: data.requestId,
            errorMessage: data.errorMessage,
            metadata: data.metadata,
        });
    }

    /**
     * Log API request
     */
    async logApiRequest(data: {
        endpoint: string;
        method: string;
        status: 'success' | 'failed' | 'error';
        statusCode: number;
        requestId?: string;
        duration: number;
        errorMessage?: string;
        metadata?: any;
    }): Promise<void> {
        await this.log({
            serviceName: 'fraugster',
            action: 'api_request',
            status: data.status,
            statusCode: data.statusCode,
            endpoint: data.endpoint,
            method: data.method,
            requestId: data.requestId,
            duration: data.duration,
            errorMessage: data.errorMessage,
            metadata: data.metadata,
        });
    }

    /**
     * Log token refresh
     */
    async logTokenRefresh(data: {
        reason: string;
        requestId?: string;
        duration: number;
    }): Promise<void> {
        await this.log({
            serviceName: 'fraugster',
            action: 'token_refresh',
            status: 'success',
            requestId: data.requestId,
            duration: data.duration,
            metadata: { reason: data.reason },
        });
    }

    /**
     * Get recent audit logs (for monitoring/debugging)
     */
    async getRecentLogs(limit: number = 100): Promise<any[]> {
        return this.prisma.auditLog.findMany({
            take: limit,
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    /**
     * Get logs by action type
     */
    async getLogsByAction(action: string, limit: number = 100): Promise<any[]> {
        return this.prisma.auditLog.findMany({
            where: {
                action,
            },
            take: limit,
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    /**
     * Get failed requests for monitoring
     */
    async getFailedRequests(hours: number = 24): Promise<any[]> {
        const since = new Date();
        since.setHours(since.getHours() - hours);

        return this.prisma.auditLog.findMany({
            where: {
                status: {
                    in: ['failed', 'error'],
                },
                createdAt: {
                    gte: since,
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    /**
     * Log webhook event
     */
    async logWebhookEvent(data: {
        eventType: string;
        payload: any;
        processed: boolean;
        timestamp: Date;
    }): Promise<void> {
        try {
            await this.prisma.auditLog.create({
                data: {
                    serviceName: 'fraugster',
                    action: 'WEBHOOK_RECEIVED',
                    status: data.processed ? 'success' : 'error',
                    endpoint: '/webhook',
                    method: 'POST',
                    statusCode: 200,
                    requestId: `webhook-${Date.now()}`,
                    duration: 0,
                    metadata: {
                        eventType: data.eventType,
                        payload: data.payload,
                        processed: data.processed,
                        timestamp: data.timestamp,
                    },
                    ipAddress: 'webhook',
                    userAgent: 'Fraugster-Webhook',
                },
            });

            this.logger.debug('📡 Webhook event logged', {
                eventType: data.eventType,
                processed: data.processed,
            });
        } catch (error) {
            // Don't throw - logging should never break the app
            this.logger.error('❌ Failed to log webhook event', {
                error: error?.message,
                data,
            });
        }
    }

    /**
     * Log transaction event
     */
    async logTransaction(data: {
        transactionId: string;
        action: string;
        status: string;
        duration?: number;
        errorMessage?: string;
        metadata?: any;
    }): Promise<void> {
        try {
            await this.prisma.auditLog.create({
                data: {
                    serviceName: 'fraugster',
                    action: data.action,
                    status: data.status,
                    endpoint: '/api/v2/transaction',
                    method: 'POST',
                    requestId: data.transactionId,
                    duration: data.duration,
                    errorMessage: data.errorMessage,
                    metadata: data.metadata,
                },
            });

            this.logger.debug('💳 Transaction logged', {
                transactionId: data.transactionId,
                action: data.action,
                status: data.status,
            });
        } catch (error) {
            // Don't throw - logging should never break the app
            this.logger.error('❌ Failed to log transaction', {
                error: error?.message,
                data,
            });
        }
    }
}
