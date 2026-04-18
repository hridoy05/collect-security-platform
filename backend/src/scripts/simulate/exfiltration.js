// ============================================================
// Simulate Data Exfiltration — for testing SIEM + ML
// Topic 5+8: Large outbound transfer anomaly
// Run: npm run simulate:exfil
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
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      }
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode }); }
      });
    });
    req.on('error', () => resolve({ status: 500 }));
    req.write(data);
    req.end();
  });
}

async function simulateExfiltration() {
  console.log('\n╔═══════════════════════════════════════════╗');
  console.log('║  Connect Security — Exfiltration Simulator   ║');
  console.log('║  UEBA: Simulates insider data theft       ║');
  console.log('╚═══════════════════════════════════════════╝\n');

  const loginRes = await post('/api/auth/login', {
    email: 'admin@connect.com', password: 'Admin@123'
  });
  const token = loginRes.data?.token || '';

  console.log('📋 Step 1: Training normal user profile...\n');

  // Build 30 days of normal behavior for user "nadia"
  const userId = 'nadia@paybdapp.com';

  for (let day = 0; day < 30; day++) {
    const hour = 9 + Math.floor(Math.random() * 9); // 9am-6pm
    await post('/api/ml/ueba/update', {
      userId,
      event: {
        timestamp: new Date(Date.now() - (30 - day) * 86400000).toISOString(),
        sourceIP: '10.0.1.' + (50 + Math.floor(Math.random() * 10)),
        country: 'Bangladesh',
        apiCalls: 20 + Math.floor(Math.random() * 30),
        bytesTransferred: 50000 + Math.floor(Math.random() * 100000),
        hour
      }
    }, token);
    process.stdout.write(`   Building profile: day ${day + 1}/30\r`);
  }

  console.log('\n   ✅ Normal profile established\n');
  console.log('🔴 Step 2: Simulating anomalous event (insider attack)...\n');

  // Anomalous event — 3am, Singapore, 3000 API calls, 500MB transfer
  const anomalousEvent = {
    timestamp: new Date().toISOString(),
    sourceIP: '103.15.20.45',
    country: 'Singapore',         // New country — impossible travel
    apiCalls: 3000,               // 100x normal
    bytesTransferred: 524288000,  // 500MB — 5000x normal
    hour: 3                       // 3am — never normal
  };

  console.log('   Anomalous behavior:');
  console.log(`   ├─ Country:   ${anomalousEvent.country} (normal: Bangladesh)`);
  console.log(`   ├─ Hour:      3am (normal: 9am-6pm)`);
  console.log(`   ├─ API calls: ${anomalousEvent.apiCalls} (normal: ~30)`);
  console.log(`   └─ Transfer:  500MB (normal: ~150KB)\n`);

  const scoreRes = await post('/api/ml/ueba/score', {
    userId, event: anomalousEvent
  }, token);

  if (scoreRes.status === 200) {
    const r = scoreRes.data;
    console.log('📊 UEBA Anomaly Score:');
    console.log(`   Score:    ${(r.score * 100).toFixed(1)}/100`);
    console.log(`   Anomaly:  ${r.isAnomaly ? '🚨 YES' : '✅ NO'}`);
    console.log(`   Severity: ${r.severity?.toUpperCase()}`);
    if (r.anomalies?.length > 0) {
      console.log('\n   Detected anomalies:');
      r.anomalies.forEach(a => console.log(`   ⚠ ${a}`));
    }
    console.log('\n✅ UEBA alert created — check http://localhost:3000/ml\n');
  } else {
    console.log('\n   ⚠ API not available — showing simulated result:\n');
    console.log('   Score:    87.0/100');
    console.log('   Anomaly:  🚨 YES');
    console.log('   Severity: CRITICAL');
    console.log('   ⚠ New country: Singapore');
    console.log('   ⚠ Unusual login hour: 3:00');
    console.log('   ⚠ API call spike: 3000 vs avg 30');
    console.log('   ⚠ Unusual data transfer: 500.0MB\n');
  }

  // Z-score demonstration on transfer sizes
  console.log('📊 Z-Score Analysis on Transfer Sizes:');
  const transferSizes = [52000, 48000, 55000, 61000, 50000, 45000, 58000, 524288000];

  const mean = transferSizes.slice(0, -1).reduce((a, b) => a + b, 0) / 7;
  const std = Math.sqrt(transferSizes.slice(0, -1).reduce((a, b) => a + Math.pow(b - mean, 2), 0) / 7);
  const lastZ = Math.abs((transferSizes[transferSizes.length - 1] - mean) / std);

  console.log(`   Normal transfers avg: ${(mean / 1000).toFixed(0)}KB`);
  console.log(`   Anomalous transfer:   ${(524288000 / 1024 / 1024).toFixed(0)}MB`);
  console.log(`   Z-Score:              ${lastZ.toFixed(1)} (threshold: 3.0)`);
  console.log(`   Result:               ${lastZ > 3 ? '🚨 ANOMALY DETECTED' : '✅ Normal'}\n`);
}

simulateExfiltration().catch(console.error);
