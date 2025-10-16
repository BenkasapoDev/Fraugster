import { Controller, Post, Get, Body, Param } from '@nestjs/common';
import { TransactionService } from './transaction.service';

@Controller()
export class TransactionController {
    constructor(private readonly transactionService: TransactionService) { }

    /**
     * POST /transaction - Send a transaction
     * Example usage showing automatic token management
     */
    @Post('transaction')
    async sendTransaction(@Body() transactionData: any) {
        return this.transactionService.sendTransaction(transactionData);
    }

    /**
     * GET /transaction/:id - Get transaction status
     */
    @Get('transaction/:id')
    async getTransactionStatus(@Param('id') id: string) {
        return this.transactionService.getTransactionStatus(id);
    }
}
