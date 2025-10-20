import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { createChildLogger } from '../logger/winston.logger';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
    private readonly logger = createChildLogger('PrismaService');

    constructor() {
        super({
            log: [
                { emit: 'event', level: 'query' },
                { emit: 'event', level: 'error' },
                { emit: 'event', level: 'info' },
                { emit: 'event', level: 'warn' },
            ],
        });

        // Log Prisma queries in development
        if (process.env.NODE_ENV !== 'production') {
            this.$on('query' as never, (e: any) => {
                this.logger.debug('Prisma Query', {
                    query: e.query,
                    params: e.params,
                    duration: `${e.duration}ms`,
                });
            });
        }

        this.$on('error' as never, (e: any) => {
            this.logger.error('Prisma Error', {
                message: e.message,
                target: e.target,
            });
        });
    }

    async onModuleInit() {
        await this.$connect();
        this.logger.info('🗄️ Database connection established', {
            provider: 'PostgreSQL',
            timestamp: new Date().toISOString(),
        });
    }

    async onModuleDestroy() {
        await this.$disconnect();
        this.logger.info('🗄️ Database connection closed', {
            timestamp: new Date().toISOString(),
        });
    }

    /**
     * Clean up expired tokens (optional maintenance task)
     */
    async cleanupExpiredTokens(): Promise<number> {
        const result = await this.authToken.deleteMany({
            where: {
                expiresAt: {
                    lt: new Date(),
                },
            },
        });

        if (result.count > 0) {
            this.logger.info('🧹 Cleaned up expired tokens', {
                count: result.count,
            });
        }

        return result.count;
    }

    /**
     * Clean up old audit logs (optional - keep last 90 days)
     */
    async cleanupOldAuditLogs(daysToKeep: number = 90): Promise<number> {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

        const result = await this.auditLog.deleteMany({
            where: {
                createdAt: {
                    lt: cutoffDate,
                },
            },
        });

        if (result.count > 0) {
            this.logger.info('🧹 Cleaned up old audit logs', {
                count: result.count,
                olderThan: cutoffDate.toISOString(),
            });
        }

        return result.count;
    }
}
