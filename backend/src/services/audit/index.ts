import type { Request, Response } from 'express';

import * as auditLogRepository from '../../repositories/audit';

async function recordRequestAudit(req: Request, res: Response, duration: number) {
  return auditLogRepository.create({
    userId: req.user?.userId || null,
    action: `${req.method} ${req.path}`,
    resource: req.path.split('/')[2] || null,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    details: { status: res.statusCode, duration }
  });
}

export {
  recordRequestAudit
};
