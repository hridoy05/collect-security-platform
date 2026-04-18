require('dotenv').config();
const bcrypt = require('bcryptjs');
const prisma = require('../config/prismaClient');

async function seed() {
  console.log('Seeding database...');

  const passwordHash = await bcrypt.hash('Admin@123', 12);

  await prisma.user.upsert({
    where: { email: 'admin@connect.com' },
    update: {},
    create: { email: 'admin@connect.com', password: passwordHash, role: 'admin', fullName: 'Connect Admin' }
  });

  await prisma.user.upsert({
    where: { email: 'analyst@connect.com' },
    update: {},
    create: { email: 'analyst@connect.com', password: passwordHash, role: 'analyst', fullName: 'Security Analyst' }
  });

  console.log('Seed complete. Users: admin@connect.com / analyst@connect.com (password: Admin@123)');
}

seed()
  .catch(err => { console.error('Seed failed:', err); process.exit(1); })
  .finally(() => prisma.$disconnect());
