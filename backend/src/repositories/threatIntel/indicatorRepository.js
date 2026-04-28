const prisma = require('../../config/prismaClient');

async function findActive(limit = 100) {
  return prisma.threatIndicator.findMany({
    where: { isActive: true },
    orderBy: [{ confidence: 'desc' }, { lastSeen: 'desc' }],
    take: limit
  });
}

async function findActiveByValueAndType(iocValue, iocType) {
  return prisma.threatIndicator.findFirst({
    where: { iocValue, iocType, isActive: true }
  });
}

async function updateLastSeen(id) {
  return prisma.threatIndicator.update({
    where: { id },
    data: { lastSeen: new Date() }
  });
}

async function create(data) {
  return prisma.threatIndicator.create({ data });
}

async function getSummary() {
  const [total, critical, ips, domains, hashes] = await Promise.all([
    prisma.threatIndicator.count({ where: { isActive: true } }),
    prisma.threatIndicator.count({ where: { isActive: true, severity: 'critical' } }),
    prisma.threatIndicator.count({ where: { isActive: true, iocType: 'ip' } }),
    prisma.threatIndicator.count({ where: { isActive: true, iocType: 'domain' } }),
    prisma.threatIndicator.count({ where: { isActive: true, iocType: 'hash' } })
  ]);

  return { total, critical, ips, domains, hashes };
}

async function countActive() {
  return prisma.threatIndicator.count({ where: { isActive: true } });
}

module.exports = {
  countActive,
  create,
  findActive,
  findActiveByValueAndType,
  getSummary,
  updateLastSeen
};
