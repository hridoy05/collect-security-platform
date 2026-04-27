require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const routes = require('./routes');
const { auditMiddleware } = require('./middleware/audit');
const { errorHandler, notFound } = require('./middleware/errorMiddleware');

function createApp() {
  const app = express();

  app.use(helmet({
    contentSecurityPolicy: false
  }));

  app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
  }));

  app.use('/api/', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, slow down.' },
    standardHeaders: true,
    legacyHeaders: false
  }));

  app.use('/api/auth/login', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts. Account temporarily locked.' }
  }));

  app.use(express.json({ limit: '10mb' }));
  app.use(auditMiddleware);
  app.use(routes);
  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = createApp;
