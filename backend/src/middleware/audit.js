// middleware/audit.js — Topic 7: Audit every API call
const { recordRequestAudit } = require('../services/audit');

async function auditMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', async () => {
    if (req.path === '/health') return; // skip health checks
    try {
      await recordRequestAudit(req, res, Date.now() - start);
    } catch (e) {
      // Non-blocking — never let audit failures break the request
      console.error('Audit log failed:', e);
    }
  });
  next();
}

module.exports = { auditMiddleware };
