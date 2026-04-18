// middleware/audit.js — Topic 7: Audit every API call
const prisma = require('../config/prismaClient');

async function auditMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', async () => {
    if (req.path === '/health') return; // skip health checks
    try {
      await prisma.auditLog.create({
        data: {
          userId: req.user?.userId || null,
          action: `${req.method} ${req.path}`,
          resource: req.path.split('/')[2] || null,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          details: { status: res.statusCode, duration: Date.now() - start }
        }
      });
    } catch (e) {
      // Non-blocking — never let audit failures break the request
      console.error('Audit log failed:', e);
    }
  });
  next();
}

module.exports = { auditMiddleware };
