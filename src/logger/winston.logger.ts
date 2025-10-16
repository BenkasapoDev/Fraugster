import * as winston from 'winston';

// Define log levels
const levels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
};

// Define colors for each level
const colors = {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'blue',
};

// Add colors to winston
winston.addColors(colors);

// Define the format for logs
const format = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
    winston.format.colorize({ all: true }),
    winston.format.printf(
        (info) => `${info.timestamp} ${info.level}: ${info.message}`,
    ),
);

// Define transports (where logs go)
const transports = [
    // Console transport for development
    new winston.transports.Console({
        format,
    }),

    // File transport for errors
    new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.errors({ stack: true }),
            winston.format.json(),
        ),
    }),

    // File transport for all logs
    new winston.transports.File({
        filename: 'logs/all.log',
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json(),
        ),
    }),
];

// Create the logger instance
export const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    levels,
    transports,
});

// If we're not in production, log to console with colors
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple(),
        ),
    }));
}

// Export a function to create child loggers that mimic NestJS Logger interface
export const createChildLogger = (context: string) => {
    const childLogger = logger.child({ context });

    // Create a wrapper that mimics NestJS Logger interface
    return {
        error: (message: string, ...optionalParams: any[]) => {
            childLogger.error(message, ...optionalParams);
        },
        warn: (message: string, ...optionalParams: any[]) => {
            childLogger.warn(message, ...optionalParams);
        },
        info: (message: string, ...optionalParams: any[]) => {
            childLogger.info(message, ...optionalParams);
        },
        log: (message: string, ...optionalParams: any[]) => {
            childLogger.info(message, ...optionalParams);
        },
        debug: (message: string, ...optionalParams: any[]) => {
            childLogger.debug(message, ...optionalParams);
        },
        verbose: (message: string, ...optionalParams: any[]) => {
            childLogger.debug(message, ...optionalParams);
        },
    };
};