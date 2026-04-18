require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function migrate() {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();

  const sqlPath = path.join(__dirname, '../../../migrations/init.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  console.log('Running migrations...');
  await client.query(sql);
  console.log('Migrations complete.');

  await client.end();
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
