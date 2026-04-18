const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://connect_admin:connect_secret_2024@localhost:5432/connect_security',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err);
});

module.exports = { pool };
