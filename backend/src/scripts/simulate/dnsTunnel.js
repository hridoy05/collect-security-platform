// ============================================================
// Simulate DNS Tunneling — for testing ML detection
// Topic 8: Triggers Shannon entropy anomaly detection
// Run: npm run simulate:dnstunnel
// ============================================================

const http = require('http');

async function post(path, body, token = '') {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: 'localhost', port: 4000, path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, data: body }); }
      });
    });
    req.on('error', e => resolve({ status: 500, error: e.message }));
    req.write(data);
    req.end();
  });
}

// Encode data as base64 to simulate DNS tunneling payload
function encodeAsSubdomain(data) {
  return Buffer.from(data).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .toLowerCase();
}

async function simulateDNSTunneling() {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║  Connect Security — DNS Tunneling Simulator   ║');
  console.log('║  Simulates data exfiltration via DNS       ║');
  console.log('╚════════════════════════════════════════════╝\n');

  // Login first
  const loginRes = await post('/api/auth/login', {
    email: 'admin@connect.com',
    password: 'Admin@123'
  });

  if (loginRes.status !== 200) {
    console.log('⚠ Could not authenticate — running offline demo\n');
  }

  const token = loginRes.data?.token || '';

  // Simulate stolen data being exfiltrated via DNS
  const stolenData = [
    'payment_card_4111111111111111',
    'user_password_hash_abc123def',
    'api_key_sk_live_paybd_secret',
    'session_token_eyJhbGciOiJIUzI1',
    'database_password_postgres_prod'
  ];

  console.log('🔴 Simulating DNS tunneling exfiltration...\n');
  console.log('   Each DNS query carries encoded stolen data:\n');

  const queries = stolenData.map(data => {
    const encoded = encodeAsSubdomain(data);
    const domain = `${encoded}.evil-c2.attacker.com`;
    console.log(`   📤 Exfiltrating: "${data}"`);
    console.log(`      DNS Query:    ${domain}`);
    console.log(`      Entropy:      high (${(3.8 + Math.random() * 0.8).toFixed(2)})\n`);
    return { name: domain };
  });

  // Add some normal queries to compare
  queries.push(
    { name: 'api.paybdapp.com' },
    { name: 'mail.google.com' },
    { name: 'cdn.jsdelivr.net' }
  );

  // Submit to ML detection
  const result = await post('/api/ml/dns-tunneling', { queries }, token);

  if (result.status === 200) {
    console.log('\n📊 ML Detection Results:');
    console.log('═══════════════════════════════════\n');
    result.data.results?.forEach(r => {
      const icon = r.isTunneling ? '🚨' : '✅';
      console.log(`${icon} ${r.query}`);
      console.log(`   Entropy: ${r.entropy} | Length: ${r.length} | Tunneling: ${r.isTunneling}`);
      if (r.isTunneling) console.log(`   ALERT: ${r.reason}`);
      console.log();
    });

    console.log(`\n🚨 Tunneling detected: ${result.data.tunnelingDetected}/${result.data.total} queries`);
    console.log('✅ ML anomaly alerts created — check http://localhost:3000/ml\n');
  } else {
    console.log('\n⚠ API not available — showing local entropy analysis:\n');
    queries.forEach(q => {
      const sub = q.name.split('.').slice(0, -2).join('.');
      const chars = sub.split('');
      const freq = {};
      chars.forEach(c => freq[c] = (freq[c] || 0) + 1);
      const entropy = Object.values(freq).reduce((e, n) => {
        const p = n / sub.length;
        return e - p * Math.log2(p);
      }, 0);
      const tunneling = entropy > 3.5 || sub.length > 40;
      console.log(`${tunneling ? '🚨' : '✅'} ${q.name}`);
      console.log(`   Entropy: ${entropy.toFixed(3)} | Tunneling: ${tunneling}\n`);
    });
  }
}

simulateDNSTunneling().catch(console.error);
