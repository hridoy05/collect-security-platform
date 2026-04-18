// ============================================================
// Simulate Brute Force Attack — for testing SIEM detection
// Topic 5: Triggers brute force correlation rule
// Run: npm run simulate:bruteforce
// ============================================================

const http = require('http');

const TARGET_HOST = 'localhost';
const TARGET_PORT = 4000;
const ATTACKER_IP = '45.33.32.156'; // Known FIN7 IP from threat intel

async function post(path, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: TARGET_HOST,
      port: TARGET_PORT,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'X-Forwarded-For': ATTACKER_IP // Simulate attacker IP
      }
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', () => resolve({ status: 500 }));
    req.write(data);
    req.end();
  });
}

async function simulateBruteForce() {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║  Connect Security — Brute Force Simulator  ║');
  console.log('║  Attacker IP: 45.33.32.156 (FIN7)       ║');
  console.log('╚════════════════════════════════════════╝\n');

  const targets = [
    'karim@paybdapp.com',
    'rahim@paybdapp.com',
    'admin@paybdapp.com'
  ];

  const passwords = [
    'password123', '123456', 'qwerty', 'abc123',
    'letmein', 'monkey', 'dragon', 'master'
  ];

  let attempts = 0;
  let failures = 0;

  console.log('🔴 Simulating credential stuffing attack...\n');

  // 50 failed attempts
  for (let i = 0; i < 50; i++) {
    const email = targets[i % targets.length];
    const password = passwords[i % passwords.length];

    const result = await post('/api/auth/login', { email, password });
    attempts++;

    if (result.status === 401) {
      failures++;
      process.stdout.write(`  ✗ Failed: ${email}:${password}\r`);
    }

    await new Promise(r => setTimeout(r, 100)); // 100ms between attempts
  }

  console.log(`\n\n  Total attempts: ${attempts}`);
  console.log(`  Failures: ${failures}`);
  console.log('\n✅ SIEM should have fired a brute force alert!');
  console.log('   Check: http://localhost:3000/alerts\n');
}

simulateBruteForce().catch(console.error);
