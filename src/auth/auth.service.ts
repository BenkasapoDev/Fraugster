import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as jwt from 'jsonwebtoken';
import { createChildLogger } from '../logger/winston.logger';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
    private readonly logger = createChildLogger('AuthService');
    private cachedToken: string | null = null;
    private tokenExpiryTime: Date | null = null;
    private tokenIssuedAt: Date | null = null;
    private readonly serviceName = 'fraugster';

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
        private readonly prisma: PrismaService,
        private readonly audit: AuditService,
    ) {
        // Load token from database on service initialization
        this.loadTokenFromDatabase();
    }

    /**
     * Authenticate with Fraugster API and cache the token
     * Token is valid for 24 hours
     */
    private async authenticate(): Promise<any> {
        const username = this.configService.get<string>('FRAUGSTER_USERNAME');
        const password = this.configService.get<string>('FRAUGSTER_PASSWORD');
        const baseUrl = this.configService.get<string>('FRAUGSTER_BASE_URL');
        const url = `${baseUrl}/api/v2/sessions`;
        const requestId = randomUUID();

        if (!username || !password) {
            throw new HttpException('Username and password must be configured', HttpStatus.BAD_REQUEST);
        }

        const startTime = Date.now();

        try {
            this.logger.info('🔐 Initiating authentication with Fraugster API', {
                url: url.replace(/\/\/[^@]*@/, '//**:**@'), // Hide credentials in logs
                username: username ? `${username.substring(0, 3)}***` : 'undefined',
                timestamp: new Date().toISOString(),
                requestId
            });

            const response = await firstValueFrom(
                this.httpService.post(url, {}, {
                    auth: {
                        username,
                        password,
                    },
                }),
            );

            const duration = Date.now() - startTime;
            const authData = response?.data;

            // Extract token - handle both object and string responses
            let token: string;
            if (typeof authData === 'string') {
                token = authData;
            } else if (authData?.sessionToken) {
                token = authData.sessionToken;
            } else if (authData?.token) {
                token = typeof authData.token === 'string' ? authData.token : authData.token.sessionToken;
            } else {
                token = authData;
            }

            this.logger.info('✅ Authentication successful', {
                responseTime: `${duration}ms`,
                tokenReceived: !!token,
                tokenLength: token ? token.length : 0,
                tokenType: typeof token,
                responseStatus: response?.status,
                timestamp: new Date().toISOString()
            });

            // Decode JWT token to extract real expiry time
            this.decodeAndCacheToken(token);

            // Save token to database for persistence
            await this.saveTokenToDatabase();

            // Log audit event
            await this.audit.logAuthentication({
                requestId,
                duration,
                metadata: {
                    tokenLength: token.length,
                    expiresAt: this.tokenExpiryTime?.toISOString(),
                    hoursValid: this.tokenExpiryTime ?
                        ((this.tokenExpiryTime.getTime() - Date.now()) / (1000 * 60 * 60)).toFixed(2) : 'unknown'
                }
            });

            this.logger.info('💾 Token cached successfully', {
                expiresAt: this.tokenExpiryTime?.toISOString(),
                issuedAt: this.tokenIssuedAt?.toISOString(),
                validForHours: this.tokenExpiryTime ?
                    ((this.tokenExpiryTime.getTime() - Date.now()) / (1000 * 60 * 60)).toFixed(2) : 'unknown'
            });

            return authData;
        } catch (error: any) {
            const duration = Date.now() - startTime;
            const statusCode = error?.response?.status;
            const statusText = error?.response?.statusText;
            const errorData = error?.response?.data;

            // Professional error logging with detailed context
            this.logger.error('❌ Authentication failed', {
                error: {
                    statusCode,
                    statusText,
                    message: errorData?.message || errorData?.error || 'Unknown error',
                    data: errorData
                },
                request: {
                    url: url.replace(/\/\/[^@]*@/, '//**:**@'), // Hide credentials
                    method: 'POST',
                    username: username ? `${username.substring(0, 3)}***` : 'undefined'
                },
                timestamp: new Date().toISOString(),
                severity: statusCode >= 500 ? 'CRITICAL' : statusCode >= 400 ? 'HIGH' : 'MEDIUM'
            });

            // Log audit event for failed authentication
            await this.audit.logAuthenticationFailure({
                requestId,
                statusCode: statusCode || 500,
                errorMessage: errorData?.message || errorData?.error || 'Authentication failed',
                metadata: {
                    statusText,
                    duration,
                    errorData
                }
            });

            if (statusCode) {
                // Use the actual HTTP status from the external API
                const errorMessage = typeof errorData === 'string' ? errorData :
                    (errorData?.message || errorData?.error || errorData?.error_msg || `${statusCode} ${statusText}`);
                throw new HttpException(errorMessage, statusCode);
            } else {
                // Network or other error
                throw new HttpException('Authentication service temporarily unavailable', HttpStatus.SERVICE_UNAVAILABLE);
            }
        }
    }

    /**
     * Load token from database if it exists and is still valid
     */
    private async loadTokenFromDatabase(): Promise<void> {
        try {
            const cached = await this.prisma.authToken.findUnique({
                where: { serviceName: this.serviceName },
            });

            if (cached) {
                // Check if token is still valid
                if (cached.expiresAt > new Date()) {
                    this.cachedToken = cached.token;
                    this.tokenExpiryTime = cached.expiresAt;
                    this.tokenIssuedAt = cached.issuedAt;

                    const timeRemaining = cached.expiresAt.getTime() - Date.now();
                    const hoursRemaining = (timeRemaining / (1000 * 60 * 60)).toFixed(2);
                    this.logger.info('📂 Token loaded from database', {
                        source: 'database',
                        hoursRemaining: parseFloat(hoursRemaining),
                        expiresAt: cached.expiresAt.toISOString(),
                        issuedAt: cached.issuedAt?.toISOString(),
                    });
                } else {
                    this.logger.warn('⚠️ Cached token expired', {
                        expiredAt: cached.expiresAt.toISOString(),
                        expiredHoursAgo: ((Date.now() - cached.expiresAt.getTime()) / (1000 * 60 * 60)).toFixed(2),
                        action: 'deleting_from_database'
                    });
                    // Delete expired token
                    await this.prisma.authToken.delete({
                        where: { serviceName: this.serviceName },
                    });
                }
            }
        } catch (error) {
            this.logger.warn('🔧 Failed to load token from database', {
                error: error?.message,
                serviceName: this.serviceName,
                action: 'will_authenticate_fresh'
            });
        }
    }

    /**
     * Save token to database for persistence across server restarts
     */
    private async saveTokenToDatabase(): Promise<void> {
        try {
            if (!this.cachedToken || !this.tokenExpiryTime) {
                this.logger.warn('⚠️ Cannot save token - missing token or expiry');
                return;
            }

            await this.prisma.authToken.upsert({
                where: { serviceName: this.serviceName },
                create: {
                    serviceName: this.serviceName,
                    token: this.cachedToken,
                    expiresAt: this.tokenExpiryTime,
                    issuedAt: this.tokenIssuedAt || new Date(),
                },
                update: {
                    token: this.cachedToken,
                    expiresAt: this.tokenExpiryTime,
                    issuedAt: this.tokenIssuedAt || new Date(),
                },
            });

            this.logger.debug('💾 Token persisted to database', {
                serviceName: this.serviceName,
                expiresAt: this.tokenExpiryTime?.toISOString()
            });
        } catch (error) {
            this.logger.error('❌ Failed to persist token to database', {
                error: error?.message,
                serviceName: this.serviceName,
                impact: 'token_will_not_survive_restart'
            });
        }
    }

    /**
     * Decode JWT token and cache it with the real expiry time
     */
    private decodeAndCacheToken(token: string): void {
        try {
            // Decode JWT token (without verification for now)
            const decoded = jwt.decode(token) as any;

            if (decoded) {
                this.cachedToken = token;

                // Extract expiry time from JWT 'exp' claim (in seconds since epoch)
                if (decoded.exp) {
                    this.tokenExpiryTime = new Date(decoded.exp * 1000);
                    const timeUntilExpiry = this.tokenExpiryTime.getTime() - Date.now();
                    const hoursUntilExpiry = (timeUntilExpiry / (1000 * 60 * 60)).toFixed(2);

                    this.logger.info('🔍 JWT token decoded successfully', {
                        algorithm: decoded.alg,
                        issuer: decoded.iss,
                        subject: decoded.sub,
                        scopes: decoded.scp,
                        expiresAt: this.tokenExpiryTime.toISOString(),
                        hoursUntilExpiry: parseFloat(hoursUntilExpiry),
                        jwtId: decoded.jti
                    });
                } else {
                    // Fallback: if no exp claim, use 48 hours
                    this.logger.warn('⚠️ JWT missing expiration claim', {
                        fallbackHours: 48,
                        action: 'using_fallback_expiry'
                    });
                    this.tokenExpiryTime = new Date(Date.now() + 48 * 60 * 60 * 1000);
                }

                // Extract issued at time from JWT 'iat' claim (optional)
                if (decoded.iat) {
                    this.tokenIssuedAt = new Date(decoded.iat * 1000);
                    this.logger.debug(`Token issued at: ${this.tokenIssuedAt.toISOString()}`);
                }

                // Log other useful JWT claims for debugging
                if (decoded.sub) {
                    this.logger.debug(`Token subject: ${decoded.sub}`);
                }
            } else {
                // Token is not a valid JWT, treat as opaque token
                this.logger.warn('⚠️ Token is not a valid JWT', {
                    tokenType: 'opaque',
                    fallbackHours: 48,
                    action: 'using_fallback_expiry'
                });
                this.cachedToken = token;
                this.tokenExpiryTime = new Date(Date.now() + 48 * 60 * 60 * 1000);
            }
        } catch (error) {
            // Error decoding token, treat as opaque token
            this.logger.error('❌ Failed to decode JWT token', {
                error: error?.message,
                tokenType: 'opaque',
                fallbackHours: 48,
                action: 'using_fallback_expiry'
            });
            this.cachedToken = token;
            this.tokenExpiryTime = new Date(Date.now() + 48 * 60 * 60 * 1000);
        }
    }

    /**
     * Get a valid token - reuses cached token if still valid, otherwise re-authenticates
     */
    async getValidToken(): Promise<string> {
        // Check if we have a valid cached token
        if (this.cachedToken && this.tokenExpiryTime && new Date() < this.tokenExpiryTime) {
            const timeRemaining = this.tokenExpiryTime.getTime() - Date.now();
            const hoursRemaining = (timeRemaining / (1000 * 60 * 60)).toFixed(2);
            this.logger.info('✅ Using cached token', {
                source: 'memory',
                hoursRemaining: parseFloat(hoursRemaining),
                expiresAt: this.tokenExpiryTime.toISOString(),
                bufferHours: 1
            });
            return this.cachedToken;
        }

        // Token expired or doesn't exist, re-authenticate
        const requestId = randomUUID();
        const startTime = Date.now();

        this.logger.warn('🔄 Token refresh required', {
            reason: this.cachedToken ? 'expired_or_expiring_soon' : 'not_cached',
            expiresAt: this.tokenExpiryTime?.toISOString(),
            action: 'initiating_fresh_authentication',
            requestId
        });

        this.cachedToken = null;
        this.tokenExpiryTime = null;

        const authResponse = await this.authenticate();

        // Log token refresh audit event
        await this.audit.logTokenRefresh({
            reason: this.cachedToken ? 'expired' : 'not_cached',
            requestId,
            duration: Date.now() - startTime,
        });

        return this.cachedToken || authResponse;
    }

    /**
     * Make an authenticated API call to Fraugster with automatic token refresh on 401
     */
    async makeAuthenticatedRequest(endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'POST', data?: any): Promise<any> {
        const baseUrl = this.configService.get<string>('FRAUGSTER_BASE_URL');
        const url = `${baseUrl}${endpoint}`;
        const requestId = randomUUID();
        const startTime = Date.now();

        try {
            const token = await this.getValidToken();

            // Add delay to prevent rate limiting with detailed logging
            const delaySeconds = 30; // Increased to 30 seconds
            this.logger.debug('⏱️ Applying rate limit delay', {
                delayMs: delaySeconds * 1000,
                delaySeconds,
                endpoint,
                method,
                reason: 'prevent_api_rate_limiting'
            });
            await new Promise(resolve => setTimeout(resolve, delaySeconds * 1000));

            const apiStartTime = Date.now();
            // Make the API call with the token
            const response = await firstValueFrom(
                this.httpService.request({
                    method,
                    url,
                    data,
                    headers: {
                        'Authorization': `SessionToken ${token}`,
                        'Content-Type': 'application/json',
                        'User-Agent': 'Fraugster-Integration/1.0',
                    },
                }),
            );

            const apiDuration = Date.now() - apiStartTime;
            const totalDuration = Date.now() - startTime;

            this.logger.info('✅ API request successful', {
                endpoint,
                method,
                statusCode: response?.status,
                responseTime: `${apiDuration}ms`,
                totalTime: `${totalDuration}ms`,
                dataSize: response?.data ? JSON.stringify(response.data).length : 0,
                timestamp: new Date().toISOString()
            });

            // Log audit event
            await this.audit.logApiRequest({
                endpoint,
                method,
                status: 'success',
                statusCode: response?.status,
                requestId,
                duration: apiDuration,
                metadata: {
                    dataSize: response?.data ? JSON.stringify(response.data).length : 0,
                    totalTime: totalDuration,
                }
            });

            return response?.data;
        } catch (error: any) {
            const duration = Date.now() - startTime;
            const statusCode = error?.response?.status;

            // If the error is already an HttpException (from authentication), re-throw it
            if (error instanceof HttpException) {
                throw error;
            }

            // If 401, token expired - clear cache and retry once
            if (statusCode === 401 && this.cachedToken) {
                this.logger.warn('🔄 Token expired (401), attempting refresh', {
                    statusCode: 401,
                    action: 'clearing_cache_and_retrying',
                    endpoint,
                    method
                });

                // Clear cached token and force re-authentication
                this.cachedToken = null;
                this.tokenExpiryTime = null;

                try {
                    const newToken = await this.getValidToken();

                    // Add delay before retry to prevent rate limiting
                    const retryDelaySeconds = 30; // Increased to 30 seconds
                    this.logger.debug('⏱️ Retry delay after token refresh', {
                        delayMs: retryDelaySeconds * 1000,
                        delaySeconds: retryDelaySeconds,
                        reason: 'prevent_rate_limiting_on_retry'
                    });
                    await new Promise(resolve => setTimeout(resolve, retryDelaySeconds * 1000));

                    // Retry the request with new token
                    const retryStartTime = Date.now();
                    const response = await firstValueFrom(
                        this.httpService.request({
                            method,
                            url,
                            data,
                            headers: {
                                'Authorization': `SessionToken ${newToken}`,
                                'Content-Type': 'application/json',
                                'User-Agent': 'Fraugster-Integration/1.0',
                            },
                        }),
                    );

                    const retryDuration = Date.now() - retryStartTime;
                    this.logger.info('✅ Request succeeded after token refresh', {
                        endpoint,
                        method,
                        retryTime: `${retryDuration}ms`,
                        statusCode: response?.status
                    });

                    // Log successful retry
                    await this.audit.logApiRequest({
                        endpoint,
                        method,
                        status: 'success',
                        statusCode: response?.status,
                        requestId,
                        duration: retryDuration,
                        metadata: {
                            retry: true,
                            reason: 'token_expired_401',
                        }
                    });

                    return response?.data;
                } catch (retryError: any) {
                    const retryDuration = Date.now() - startTime;

                    this.logger.error('❌ Request failed after token refresh', {
                        error: {
                            statusCode: retryError?.response?.status,
                            statusText: retryError?.response?.statusText,
                            message: retryError?.response?.data?.message || retryError?.message,
                            data: retryError?.response?.data
                        },
                        request: {
                            endpoint,
                            method,
                            url,
                            attempt: 'retry_after_token_refresh'
                        },
                        timestamp: new Date().toISOString(),
                        severity: 'CRITICAL'
                    });

                    // Log failed retry
                    await this.audit.logApiRequest({
                        endpoint,
                        method,
                        status: 'error',
                        statusCode: retryError?.response?.status || 500,
                        requestId,
                        duration: retryDuration,
                        errorMessage: retryError?.response?.data?.message || retryError?.message,
                        metadata: {
                            retry: true,
                            reason: 'token_expired_401',
                            errorData: retryError?.response?.data,
                        }
                    });

                    throw new HttpException(
                        retryError?.response?.data || 'Request failed after re-authentication',
                        retryError?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
                    );
                }
            }

            // For rate limiting errors
            if (statusCode === 400 && error?.response?.data?.message?.includes('rate limit')) {
                this.logger.error('🚫 Rate limit exceeded', {
                    error: {
                        statusCode,
                        message: error?.response?.data?.message,
                        rateLimitType: 'api_enforced'
                    },
                    request: {
                        endpoint,
                        method,
                        url,
                        hasData: !!data
                    },
                    suggestion: 'increase_delay_or_check_request_frequency',
                    timestamp: new Date().toISOString(),
                    severity: 'HIGH'
                });

                // Log rate limit error
                await this.audit.logApiRequest({
                    endpoint,
                    method,
                    status: 'error',
                    statusCode: HttpStatus.TOO_MANY_REQUESTS,
                    requestId,
                    duration,
                    errorMessage: 'Enforce rate limit',
                    metadata: {
                        originalStatusCode: statusCode,
                        errorData: error?.response?.data,
                    }
                });

                throw new HttpException('Enforce rate limit', HttpStatus.TOO_MANY_REQUESTS);
            }

            // For other errors, throw immediately
            const errorData = error?.response?.data;
            this.logger.error('❌ API request failed', {
                error: {
                    statusCode,
                    statusText: error?.response?.statusText,
                    message: errorData?.message || errorData?.error || errorData?.error_msg || 'Unknown error',
                    data: errorData,
                    stack: error?.stack
                },
                request: {
                    endpoint,
                    method,
                    url,
                    hasData: !!data,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'SessionToken [HIDDEN]'
                    }
                },
                timestamp: new Date().toISOString(),
                severity: statusCode >= 500 ? 'CRITICAL' : statusCode >= 400 ? 'HIGH' : 'MEDIUM'
            });

            // Log failed request
            await this.audit.logApiRequest({
                endpoint,
                method,
                status: 'failed',
                statusCode: statusCode || 500,
                requestId,
                duration,
                errorMessage: errorData?.message || errorData?.error || error?.message,
                metadata: {
                    errorData,
                    statusText: error?.response?.statusText,
                }
            });

            // Build a clear error message
            let errorMessage: string;
            if (errorData) {
                if (typeof errorData === 'string') {
                    errorMessage = errorData;
                } else {
                    errorMessage = errorData?.message || errorData?.error || errorData?.error_msg || JSON.stringify(errorData);
                }
            } else if (statusCode && error?.response?.statusText) {
                errorMessage = `${statusCode} ${error?.response?.statusText}`;
            } else {
                errorMessage = error?.message || 'Request failed due to network or server error';
            }

            throw new HttpException(errorMessage, statusCode || HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Manual login endpoint (for testing or initial setup)
     */
    async login(): Promise<any> {
        return this.authenticate();
    }

    /**
     * Clear cached token (useful for logout or force refresh)
     */
    async clearToken(): Promise<void> {
        this.cachedToken = null;
        this.tokenExpiryTime = null;
        this.tokenIssuedAt = null;

        // Delete token from database
        try {
            await this.prisma.authToken.delete({
                where: { serviceName: this.serviceName },
            });
            this.logger.log('Token cache cleared (memory and database)');
        } catch (error) {
            if (error?.code === 'P2025') {
                // Record not found - already deleted
                this.logger.log('Token cache cleared (memory only - no database record)');
            } else {
                this.logger.error('Failed to delete token from database:', error?.message);
            }
        }
    }

    /**
     * Get token info (for debugging/monitoring)
     */
    getTokenInfo(): any {
        if (!this.cachedToken) {
            return { cached: false, message: 'No token cached' };
        }

        const now = new Date();
        const timeUntilExpiry = this.tokenExpiryTime ? this.tokenExpiryTime.getTime() - now.getTime() : 0;
        const hoursUntilExpiry = (timeUntilExpiry / (1000 * 60 * 60)).toFixed(2);

        return {
            cached: true,
            issuedAt: this.tokenIssuedAt?.toISOString(),
            expiresAt: this.tokenExpiryTime?.toISOString(),
            hoursUntilExpiry: parseFloat(hoursUntilExpiry),
            isExpired: this.tokenExpiryTime ? now >= this.tokenExpiryTime : true,
        };
    }

    /**
     * Get recent audit logs (for debugging/monitoring)
     */
    async getRecentAuditLogs(limit: number = 20) {
        return this.audit.getRecentLogs(limit);
    }
}