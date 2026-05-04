import type { Express } from 'express';

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import routes from './routes';
import { auditMiddleware } from './middleware/audit';
import { errorHandler, notFound } from './middleware/errorMiddleware';

function createApp(): Express {
  const app: Express = express();

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

export default createApp;
