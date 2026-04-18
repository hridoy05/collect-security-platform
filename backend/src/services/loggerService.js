const winston = require('winston');
const { indexAppLog } = require('./elasticService');

// Custom format for clean console output
const consoleFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `[${timestamp}] ${level}: ${message}`;
  if (Object.keys(metadata).length > 0 && metadata.service !== 'connect-security') {
    msg += ` ${JSON.stringify(metadata)}`;
  }
  return msg;
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
  transports: [
    new winston.transports.Console()
  ]
});

// Wrapper service to bridge Winston with Elasticsearch
const logger = {
  info: (message, meta = {}) => {
    winstonLogger.info(message, meta);
    indexAppLog({ level: 'info', message, service: 'backend', metadata: meta });
  },
  warn: (message, meta = {}) => {
    winstonLogger.warn(message, meta);
    indexAppLog({ level: 'warn', message, service: 'backend', metadata: meta });
  },
  error: (message, meta = {}) => {
    // metadata can be an Error object
    const metaData = meta instanceof Error ? { stack: meta.stack, message: meta.message } : meta;
    winstonLogger.error(message, metaData);
    indexAppLog({ level: 'error', message: message || metaData.message, service: 'backend', metadata: metaData });
  },
  debug: (message, meta = {}) => {
    winstonLogger.debug(message, meta);
    // Usually don't send debug logs to ES to save space
  }
};

module.exports = logger;
