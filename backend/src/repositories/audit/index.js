const prisma = require('../../config/prismaClient');

async function create(data) {
  return prisma.auditLog.create({ data });
}

module.exports = {
  create
};
