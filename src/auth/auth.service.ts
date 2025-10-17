import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as jwt from 'jsonwebtoken';
import { createChildLogger } from '../logger/winston.logger';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class AuthService {
    private readonly logger = createChildLogger('AuthService');
    private cachedToken: string | null = null;
    private tokenExpiryTime: Date | null = null;
    private tokenIssuedAt: Date | null = null;
    private readonly tokenCacheFile = path.join(process.cwd(), '.token-cache.json');

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        // Load token from file on service initialization
        this.loadTokenFromFile();
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

        if (!username || !password) {
            throw new HttpException('Username and password must be configured', HttpStatus.BAD_REQUEST);
        }

        try {
            this.logger.info('🔐 Initiating authentication with Fraugster API', {
                url: url.replace(/\/\/[^@]*@/, '//**:**@'), // Hide credentials in logs
                username: username ? `${username.substring(0, 3)}***` : 'undefined',
                timestamp: new Date().toISOString(),
                requestId: Math.random().toString(36).substring(7)
            });

            const startTime = Date.now();
            const response = await firstValueFrom(
                this.httpService.post(url, {}, {
                    auth: {
                        username,
                        password,
                    },
                }),
            );

            const responseTime = Date.now() - startTime;
            const authData = response?.data;
            const token = authData?.token || authData?.session_id || authData;

            this.logger.info('✅ Authentication successful', {
                responseTime: `${responseTime}ms`,
                tokenReceived: !!token,
                tokenLength: token ? token.length : 0,
                responseStatus: response?.status,
                timestamp: new Date().toISOString()
            });

            // Decode JWT token to extract real expiry time
            this.decodeAndCacheToken(token);

            // Save token to file for persistence
            this.saveTokenToFile();

            this.logger.info('💾 Token cached successfully', {
                expiresAt: this.tokenExpiryTime?.toISOString(),
                issuedAt: this.tokenIssuedAt?.toISOString(),
                validForHours: this.tokenExpiryTime ?
                    ((this.tokenExpiryTime.getTime() - Date.now()) / (1000 * 60 * 60)).toFixed(2) : 'unknown'
            });

            return authData;
        } catch (error: any) {
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
     * Load token from file if it exists and is still valid
     */
    private loadTokenFromFile(): void {
        try {
            if (fs.existsSync(this.tokenCacheFile)) {
                const data = fs.readFileSync(this.tokenCacheFile, 'utf-8');
                const cached = JSON.parse(data);

                // Check if token is still valid
                const expiryTime = new Date(cached.expiryTime);
                if (expiryTime > new Date()) {
                    this.cachedToken = cached.token;
                    this.tokenExpiryTime = expiryTime;
                    this.tokenIssuedAt = cached.issuedAt ? new Date(cached.issuedAt) : null;

                    const timeRemaining = expiryTime.getTime() - Date.now();
                    const hoursRemaining = (timeRemaining / (1000 * 60 * 60)).toFixed(2);
                    this.logger.info('📂 Token loaded from cache file', {
                        source: 'file',
                        hoursRemaining: parseFloat(hoursRemaining),
                        expiresAt: expiryTime.toISOString(),
                        issuedAt: this.tokenIssuedAt?.toISOString(),
                        cacheFile: this.tokenCacheFile
                    });
                } else {
                    this.logger.warn('⚠️ Cached token expired', {
                        expiredAt: expiryTime.toISOString(),
                        expiredHoursAgo: ((Date.now() - expiryTime.getTime()) / (1000 * 60 * 60)).toFixed(2),
                        action: 'deleting_cache_file'
                    });
                    fs.unlinkSync(this.tokenCacheFile); // Delete expired token
                }
            }
        } catch (error) {
            this.logger.warn('🔧 Failed to load token from cache file', {
                error: error?.message,
                cacheFile: this.tokenCacheFile,
                action: 'will_authenticate_fresh'
            });
        }
    }

    /**
     * Save token to file for persistence across server restarts
     */
    private saveTokenToFile(): void {
        try {
            const data = {
                token: this.cachedToken,
                expiryTime: this.tokenExpiryTime?.toISOString(),
                issuedAt: this.tokenIssuedAt?.toISOString(),
            };
            fs.writeFileSync(this.tokenCacheFile, JSON.stringify(data, null, 2), 'utf-8');
            this.logger.debug('💾 Token persisted to cache file', {
                cacheFile: this.tokenCacheFile,
                expiresAt: this.tokenExpiryTime?.toISOString()
            });
        } catch (error) {
            this.logger.error('❌ Failed to persist token to cache file', {
                error: error?.message,
                cacheFile: this.tokenCacheFile,
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
        this.logger.warn('🔄 Token refresh required', {
            reason: this.cachedToken ? 'expired_or_expiring_soon' : 'not_cached',
            expiresAt: this.tokenExpiryTime?.toISOString(),
            action: 'initiating_fresh_authentication'
        });
        this.cachedToken = null;
        this.tokenExpiryTime = null;

        const authResponse = await this.authenticate();
        return this.cachedToken || authResponse;
    }

    /**
     * Make an authenticated API call to Fraugster with automatic token refresh on 401
     */
    async makeAuthenticatedRequest(endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'POST', data?: any): Promise<any> {
        const baseUrl = this.configService.get<string>('FRAUGSTER_BASE_URL');
        const url = `${baseUrl}${endpoint}`;

        try {
            const token = await this.getValidToken();

            // Add delay to prevent rate limiting with detailed logging
            this.logger.debug('⏱️ Applying rate limit delay', {
                delayMs: 15000,
                endpoint,
                method,
                reason: 'prevent_api_rate_limiting'
            });
            await new Promise(resolve => setTimeout(resolve, 15000));

            const startTime = Date.now();
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

            const responseTime = Date.now() - startTime;
            this.logger.info('✅ API request successful', {
                endpoint,
                method,
                statusCode: response?.status,
                responseTime: `${responseTime}ms`,
                dataSize: response?.data ? JSON.stringify(response.data).length : 0,
                timestamp: new Date().toISOString()
            });

            return response?.data;
        } catch (error: any) {
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
                    this.logger.debug('⏱️ Retry delay after token refresh', {
                        delayMs: 15000,
                        reason: 'prevent_rate_limiting_on_retry'
                    });
                    await new Promise(resolve => setTimeout(resolve, 15000));

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

                    const retryTime = Date.now() - retryStartTime;
                    this.logger.info('✅ Request succeeded after token refresh', {
                        endpoint,
                        method,
                        retryTime: `${retryTime}ms`,
                        statusCode: response?.status
                    });
                    return response?.data;
                } catch (retryError: any) {
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
    clearToken(): void {
        this.cachedToken = null;
        this.tokenExpiryTime = null;
        this.tokenIssuedAt = null;

        // Delete token file
        try {
            if (fs.existsSync(this.tokenCacheFile)) {
                fs.unlinkSync(this.tokenCacheFile);
                this.logger.log('Token cache cleared (memory and file)');
            } else {
                this.logger.log('Token cache cleared (memory only)');
            }
        } catch (error) {
            this.logger.error('Failed to delete token file:', error?.message);
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
}