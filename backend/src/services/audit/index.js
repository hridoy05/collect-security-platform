const auditLogRepository = require('../../repositories/audit');

async function recordRequestAudit(req, res, duration) {
  return auditLogRepository.create({
    userId: req.user?.userId || null,
    action: `${req.method} ${req.path}`,
    resource: req.path.split('/')[2] || null,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    details: { status: res.statusCode, duration }
  });
}

module.exports = {
  recordRequestAudit
};
