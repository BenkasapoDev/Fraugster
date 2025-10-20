import { Controller, Post, Delete, Get } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    /**
     * POST /auth/session - Manually trigger authentication
     * This will return and cache the token
     */
    @Post('session')
    async createSession() {
        return this.authService.login();
    }

    /**
     * GET /auth/token - Get current valid token (reuses cached if available)
     */
    @Get('token')
    async getToken() {
        const token = await this.authService.getValidToken();
        return { token };
    }

    /**
     * DELETE /auth/session - Clear cached token (logout)
     */
    @Delete('session')
    async clearSession() {
        this.authService.clearToken();
        return { message: 'Token cache cleared' };
    }

    /**
     * GET /auth/token-info - Get token information (for debugging/monitoring)
     */
    @Get('token-info')
    async getTokenInfo() {
        return this.authService.getTokenInfo();
    }

    /**
     * GET /auth/audit-logs - Get recent audit logs
     */
    @Get('audit-logs')
    async getAuditLogs() {
        return this.authService.getRecentAuditLogs();
    }
}