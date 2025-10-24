import { Controller, Post, Body, Headers, HttpStatus, HttpException, Logger } from '@nestjs/common';
import { WebhookService } from './webhook.service';


@Controller('webhook')
export class WebhookController {
    private readonly logger = new Logger(WebhookController.name);

    constructor(private readonly webhookService: WebhookService) { }

    @Post()
    async handleWebhook(
        @Body() payload: any,
        @Headers() headers: Record<string, string>,
    ) {
        try {
            // Validate webhook authenticity
            const isValid = await this.webhookService.validateWebhook(
                payload,
                headers,
            );

            if (!isValid) {
                throw new HttpException('Invalid webhook signature', HttpStatus.UNAUTHORIZED);
            }

            // Process the webhook event
            await this.webhookService.processWebhookEvent(payload);

            // Return 200 to acknowledge receipt (as per Fraugster docs)
            return { status: 'ok', received: true };
        } catch (error) {
            this.logger.error('Webhook processing failed', {
                error: error.message,
                payload,
                headers: {
                    'x-fraugsterwebhook-timestamp': headers['x-fraugsterwebhook-timestamp'],
                    'x-fraugsterwebhook-signature': headers['x-fraugsterwebhook-signature']?.substring(0, 10) + '...',
                },
            });
            throw error;
        }
    }
}