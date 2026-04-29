const prisma = require('../../config/prismaClient');

async function findByEmail(email) {
  return prisma.user.findUnique({ where: { email } });
}

async function findProfileById(id) {
  return prisma.user.findUnique({
    where: { id },
    select: { id: true, email: true, role: true, fullName: true, lastLogin: true }
  });
}

async function updateLastLogin(id) {
  return prisma.user.update({
    where: { id },
    data: { lastLogin: new Date() }
  });
}

module.exports = {
  findByEmail,
  findProfileById,
  updateLastLogin
};
