import prisma from '../../config/prismaClient';

async function create(data) {
  return prisma.mlAnomaly.create({ data });
}

async function findRecent(limit = 50) {
  return prisma.mlAnomaly.findMany({
    where: { isAnomaly: true },
    orderBy: { createdAt: 'desc' },
    take: limit
  });
}

export {
  create,
  findRecent
};
