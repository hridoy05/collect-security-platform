const prisma = require('../../config/prismaClient');

function toApiAlert(alert) {
  return {
    ...alert,
    alert_id: alert.alertId,
    source_type: alert.sourceType,
    source_ip: alert.sourceIp,
    dest_ip: alert.destIp,
    affected_user: alert.affectedUser,
    affected_system: alert.affectedSystem,
    mitre_tactic: alert.mitreTactic,
    mitre_technique: alert.mitreTechnique,
    alert_score: alert.alertScore,
    es_index: alert.esIndex,
    raw_event: alert.rawEvent,
    threat_intel: alert.threatIntel,
    assigned_to: alert.assignedTo,
    resolved_at: alert.resolvedAt,
    created_at: alert.createdAt,
    updated_at: alert.updatedAt
  };
}

async function findMany(filters = {}) {
  const where = {};

  if (filters.severity) {
    where.severity = filters.severity;
  }

  if (filters.status) {
    where.status = filters.status;
  }

  return prisma.securityAlert.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: filters.limit || 50
  });
}

async function countOpenStats() {
  const [critical_open, high_open, total_open, last_24h] = await Promise.all([
    prisma.securityAlert.count({ where: { severity: 'critical', status: 'open' } }),
    prisma.securityAlert.count({ where: { severity: 'high', status: 'open' } }),
    prisma.securityAlert.count({ where: { status: 'open' } }),
    prisma.securityAlert.count({
      where: { createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
    })
  ]);

  return { critical_open, high_open, total_open, last_24h };
}

async function create(data) {
  return prisma.securityAlert.create({ data });
}

async function updateStatus(id, status) {
  return prisma.securityAlert.update({
    where: { id },
    data: {
      status,
      resolvedAt: status === 'resolved' ? new Date() : null,
      updatedAt: new Date()
    }
  });
}

async function findRecentBySourceIp(sourceIp, since) {
  return prisma.securityAlert.findFirst({
    where: {
      sourceIp,
      createdAt: { gte: since }
    }
  });
}

async function findRecentForDashboard(since) {
  return prisma.securityAlert.findMany({
    where: { createdAt: { gte: since } },
    select: { createdAt: true, mitreTactic: true, title: true }
  });
}

module.exports = {
  countOpenStats,
  create,
  findMany,
  findRecentForDashboard,
  findRecentBySourceIp,
  toApiAlert,
  updateStatus
};
