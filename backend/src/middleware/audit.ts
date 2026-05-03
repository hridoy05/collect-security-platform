import type { NextFunction, Request, Response } from 'express';

// middleware/audit.js — Topic 7: Audit every API call
import { recordRequestAudit } from '../services/audit';

function auditMiddleware(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  res.on('finish', async () => {
    if (req.path === '/health') return; // skip health checks
    try {
      await recordRequestAudit(req, res, Date.now() - start);
    } catch (error) {
      // Non-blocking — never let audit failures break the request
      console.error('Audit log failed:', error);
    }
  });
  next();
}

export { auditMiddleware };
