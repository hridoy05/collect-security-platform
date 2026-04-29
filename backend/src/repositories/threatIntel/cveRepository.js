const prisma = require('../../config/prismaClient');

async function findMany(limit = 50) {
  return prisma.cveTracking.findMany({
    orderBy: [{ isKev: 'desc' }, { cvssScore: 'desc' }],
    take: limit
  });
}

async function updateStatus(id, status) {
  return prisma.cveTracking.update({
    where: { id },
    data: {
      status,
      patchedAt: status === 'patched' ? new Date() : null,
      updatedAt: new Date()
    }
  });
}

async function getSummary() {
  const [total, kev_open, critical_open, avgCvssResult] = await Promise.all([
    prisma.cveTracking.count(),
    prisma.cveTracking.count({ where: { isKev: true, status: 'open' } }),
    prisma.cveTracking.count({ where: { cvssScore: { gte: 9.0 }, status: 'open' } }),
    prisma.cveTracking.aggregate({
      where: { status: 'open' },
      _avg: { cvssScore: true }
    })
  ]);

  return {
    total,
    kev_open,
    critical_open,
    avg_cvss: avgCvssResult._avg.cvssScore
  };
}

async function getDashboardStats() {
  const [kev_open, critical_open] = await Promise.all([
    prisma.cveTracking.count({ where: { isKev: true, status: 'open' } }),
    prisma.cveTracking.count({ where: { cvssScore: { gte: 9.0 }, status: 'open' } })
  ]);

  return { kev_open, critical_open };
}

module.exports = {
  findMany,
  getDashboardStats,
  getSummary,
  updateStatus
};
