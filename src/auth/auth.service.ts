import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as jwt from 'jsonwebtoken';
import { createChildLogger } from '../logger/winston.logger';

@Injectable()
export class AuthService {
    private readonly logger = createChildLogger('AuthService');
    private cachedToken: string | null = null;
    private tokenExpiryTime: Date | null = null;
    private tokenIssuedAt: Date | null = null;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) { }

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
            this.logger.log('Authenticating with Fraugster API...');
            this.logger.debug(`Auth URL: ${url}`);
            this.logger.debug(`Username configured: ${!!username}`);
            this.logger.debug(`Password configured: ${!!password}`);

            const response = await firstValueFrom(
                this.httpService.post(url, {}, {
                    auth: {
                        username,
                        password,
                    },
                }),
            );

            const authData = response?.data;
            const token = authData?.token || authData?.session_id || authData;

            this.logger.debug(`Auth response received: ${!!authData}`);
            this.logger.debug(`Token extracted: ${!!token}`);

            // Decode JWT token to extract real expiry time
            this.decodeAndCacheToken(token);

            this.logger.log(`Authentication successful, token cached until ${this.tokenExpiryTime?.toISOString()}`);

            return authData;
        } catch (error: any) {
            const statusCode = error?.response?.status;
            const statusText = error?.response?.statusText;
            const errorData = error?.response?.data;

            // Professional error logging
            this.logger.error('Authentication failed:', {
                statusCode,
                statusText,
                errorData,
                timestamp: new Date().toISOString(),
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

                    this.logger.log(`Token decoded successfully. Expires in ${hoursUntilExpiry} hours`);
                } else {
                    // Fallback: if no exp claim, use 23 hours
                    this.logger.warn('JWT does not contain exp claim, using 23-hour fallback');
                    this.tokenExpiryTime = new Date(Date.now() + 23 * 60 * 60 * 1000);
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
                this.logger.warn('Token is not a valid JWT, using 23-hour fallback expiry');
                this.cachedToken = token;
                this.tokenExpiryTime = new Date(Date.now() + 23 * 60 * 60 * 1000);
            }
        } catch (error) {
            // Error decoding token, treat as opaque token
            this.logger.error('Failed to decode JWT token:', error?.message);
            this.logger.warn('Using 23-hour fallback expiry');
            this.cachedToken = token;
            this.tokenExpiryTime = new Date(Date.now() + 23 * 60 * 60 * 1000);
        }
    }

    /**
     * Get a valid token - reuses cached token if still valid, otherwise re-authenticates
     */
    async getValidToken(): Promise<string> {
        // Check if we have a valid cached token
        if (this.cachedToken && this.tokenExpiryTime && new Date() < this.tokenExpiryTime) {
            this.logger.debug('Using cached token');
            return this.cachedToken;
        }

        // Token expired or doesn't exist, re-authenticate
        this.logger.log('Token expired or not found, re-authenticating...');
        this.cachedToken = null;
        this.tokenExpiryTime = null;

        const authResponse = await this.authenticate();
        return this.cachedToken || authResponse;
    }

    /**
     * Make an authenticated API call to Fraugster with automatic token refresh on 401
     */
    async makeAuthenticatedRequest(endpoint: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'POST', data?: any): Promise<any> {
        const baseUrl = this.configService.get<string>('FRAUGSTER_BASE_URL') || 'https://api.fraugsterapi.com';
        const url = `${baseUrl}${endpoint}`;

        try {
            const token = await this.getValidToken();

            // Make the API call with the token
            const response = await firstValueFrom(
                this.httpService.request({
                    method,
                    url,
                    data,
                    headers: {
                        'Authorization': `SessionToken ${token}`,
                        'Content-Type': 'application/json',
                    },
                }),
            );

            return response?.data;
        } catch (error: any) {
            const statusCode = error?.response?.status;

            // If the error is already an HttpException (from authentication), re-throw it
            if (error instanceof HttpException) {
                throw error;
            }

            // If 401, token expired - clear cache and retry once
            if (statusCode === 401 && this.cachedToken) {
                this.logger.warn('Token expired (401), clearing cache and retrying with new token...');

                // Clear cached token and force re-authentication
                this.cachedToken = null;
                this.tokenExpiryTime = null;

                try {
                    const newToken = await this.getValidToken();

                    // Retry the request with new token
                    const response = await firstValueFrom(
                        this.httpService.request({
                            method,
                            url,
                            data,
                            headers: {
                                'Authorization': `SessionToken ${newToken}`,
                                'Content-Type': 'application/json',
                            },
                        }),
                    );

                    this.logger.log('Request succeeded after token refresh');
                    return response?.data;
                } catch (retryError: any) {
                    this.logger.error('Request failed after token refresh:', {
                        statusCode: retryError?.response?.status,
                        errorData: retryError?.response?.data,
                    });
                    throw new HttpException(
                        retryError?.response?.data || 'Request failed after re-authentication',
                        retryError?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
                    );
                }
            }

            // For other errors, throw immediately
            const errorData = error?.response?.data;
            this.logger.error('API request failed:', {
                statusCode,
                statusText: error?.response?.statusText,
                errorData,
                endpoint,
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
        this.logger.log('Token cache cleared');
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