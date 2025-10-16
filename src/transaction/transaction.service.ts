import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class TransactionService {
    constructor(private readonly authService: AuthService) { }

    /**
     * Example: Send a transaction to Fraugster API
     * This will automatically handle token caching and refresh
     */
    async sendTransaction(transactionData: any): Promise<any> {
        return this.authService.makeAuthenticatedRequest(
            '/api/v2/transactions',
            'POST',
            transactionData,
        );
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
