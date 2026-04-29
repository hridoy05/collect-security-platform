const winston = require('winston');
const { indexAppLog } = require('../../repositories/logging');

const consoleFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let line = `[${timestamp}] ${level}: ${message}`;

  if (Object.keys(metadata).length > 0 && metadata.service !== 'connect-security') {
    line += ` ${JSON.stringify(metadata)}`;
  }

  return line;
});

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
  info(message, meta = {}) {
    winstonLogger.info(message, meta);
    indexAppLog({ level: 'info', message, service: 'backend', metadata: meta });
  },
  warn(message, meta = {}) {
    winstonLogger.warn(message, meta);
    indexAppLog({ level: 'warn', message, service: 'backend', metadata: meta });
  },
  error(message, meta = {}) {
    const metadata = meta instanceof Error ? { stack: meta.stack, message: meta.message } : meta;
    winstonLogger.error(message, metadata);
    indexAppLog({
      level: 'error',
      message: message || metadata.message,
      service: 'backend',
      metadata
    });
  },
  debug(message, meta = {}) {
    winstonLogger.debug(message, meta);
  }
};

module.exports = logger;
