import prisma from '../../config/prismaClient';

async function create(data) {
  return prisma.auditLog.create({ data });
}

export {
  create
};
