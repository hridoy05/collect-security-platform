import winston from 'winston';
import { indexAppLog } from '../../repositories/logging';

type LogMetadata = Record<string, unknown>;
type LogMetaInput = LogMetadata | Error;

const consoleFormat = winston.format.printf(
  ({
    level,
    message,
    timestamp,
    ...metadata
  }: {
    level: string;
    message: string;
    timestamp: string;
    [key: string]: unknown;
  }) => {
    let line = `[${timestamp}] ${level}: ${message}`;

    if (Object.keys(metadata).length > 0 && metadata.service !== 'connect-security') {
      line += ` ${JSON.stringify(metadata)}`;
    }

    return line;
  }
);

const winstonLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.metadata({ fillWith: ['service', 'userId', 'path'] }),
    winston.format.colorize(),
    consoleFormat
  ),
  defaultMeta: { service: 'connect-security' },
  transports: [new winston.transports.Console()]
});

const logger = {
  info(message: string, meta: LogMetadata = {}) {
    winstonLogger.info(message, meta);
    indexAppLog({ level: 'info', message, service: 'backend', metadata: meta });
  },
  warn(message: string, meta: LogMetadata = {}) {
    winstonLogger.warn(message, meta);
    indexAppLog({ level: 'warn', message, service: 'backend', metadata: meta });
  },
  error(message: string, meta: LogMetaInput = {}) {
    const metadata =
      meta instanceof Error ? { stack: meta.stack, message: meta.message } : meta;
    const fallbackMessage =
      typeof metadata.message === 'string' ? metadata.message : 'Unknown logger error';

    winstonLogger.error(message, metadata);
    indexAppLog({
      level: 'error',
      message: message || fallbackMessage,
      service: 'backend',
      metadata
    });
  },
  debug(message: string, meta: LogMetadata = {}) {
    winstonLogger.debug(message, meta);
  }
};

export default logger;
