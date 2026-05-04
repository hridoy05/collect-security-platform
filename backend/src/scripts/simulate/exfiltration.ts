// ============================================================
// Simulate Data Exfiltration — for testing SIEM + ML
// Topic 5+8: Large outbound transfer anomaly
// Run: npm run simulate:exfil
// ============================================================

import http from 'node:http';

interface ApiResponse<T = unknown> {
  status: number;
  data?: T;
}

interface LoginResponse {
  token?: string;
}

interface UebaScoreResponse {
  score: number;
  isAnomaly: boolean;
  severity?: string;
  anomalies?: string[];
}

async function post<T = unknown>(
  path: string,
  body: Record<string, unknown>,
  token = ''
): Promise<ApiResponse<T>> {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        hostname: 'localhost',
        port: 4000,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        }
      },
      (res) => {
        let responseBody = '';
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode ?? 500, data: JSON.parse(responseBody) as T });
          } catch {
            resolve({ status: res.statusCode ?? 500 });
          }
        });
      }
    );

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

  const loginRes = await post<LoginResponse>('/api/auth/login', {
    email: 'admin@connect.com',
    password: 'Admin@123'
  });
  const token = loginRes.data?.token || '';

  console.log('Step 1: Training normal user profile...\n');

  const userId = 'nadia@paybdapp.com';

  for (let day = 0; day < 30; day += 1) {
    const hour = 9 + Math.floor(Math.random() * 9);
    await post(
      '/api/ml/ueba/update',
      {
        userId,
        event: {
          timestamp: new Date(Date.now() - (30 - day) * 86400000).toISOString(),
          sourceIP: `10.0.1.${50 + Math.floor(Math.random() * 10)}`,
          country: 'Bangladesh',
          apiCalls: 20 + Math.floor(Math.random() * 30),
          bytesTransferred: 50000 + Math.floor(Math.random() * 100000),
          hour
        }
      },
      token
    );
    process.stdout.write(`   Building profile: day ${day + 1}/30\r`);
  }

  console.log('\n   Normal profile established\n');
  console.log('Step 2: Simulating anomalous event (insider attack)...\n');

  const anomalousEvent = {
    timestamp: new Date().toISOString(),
    sourceIP: '103.15.20.45',
    country: 'Singapore',
    apiCalls: 3000,
    bytesTransferred: 524288000,
    hour: 3
  };

  console.log('   Anomalous behavior:');
  console.log(`   Country:   ${anomalousEvent.country} (normal: Bangladesh)`);
  console.log('   Hour:      3am (normal: 9am-6pm)');
  console.log(`   API calls: ${anomalousEvent.apiCalls} (normal: ~30)`);
  console.log('   Transfer:  500MB (normal: ~150KB)\n');

  const scoreRes = await post<UebaScoreResponse>('/api/ml/ueba/score', { userId, event: anomalousEvent }, token);

  if (scoreRes.status === 200 && scoreRes.data) {
    const result = scoreRes.data;
    console.log('UEBA Anomaly Score:');
    console.log(`   Score:    ${(result.score * 100).toFixed(1)}/100`);
    console.log(`   Anomaly:  ${result.isAnomaly ? 'YES' : 'NO'}`);
    console.log(`   Severity: ${result.severity?.toUpperCase()}`);
    if (result.anomalies?.length) {
      console.log('\n   Detected anomalies:');
      result.anomalies.forEach((anomaly) => console.log(`   ${anomaly}`));
    }
    console.log('\nUEBA alert created — check http://localhost:3000/ml\n');
  } else {
    console.log('\nAPI not available — showing simulated result:\n');
    console.log('   Score:    87.0/100');
    console.log('   Anomaly:  YES');
    console.log('   Severity: CRITICAL');
    console.log('   New country: Singapore');
    console.log('   Unusual login hour: 3:00');
    console.log('   API call spike: 3000 vs avg 30');
    console.log('   Unusual data transfer: 500.0MB\n');
  }

  console.log('Z-Score Analysis on Transfer Sizes:');
  const transferSizes = [52000, 48000, 55000, 61000, 50000, 45000, 58000, 524288000];
  const mean = transferSizes.slice(0, -1).reduce((a, b) => a + b, 0) / 7;
  const std = Math.sqrt(
    transferSizes.slice(0, -1).reduce((a, b) => a + Math.pow(b - mean, 2), 0) / 7
  );
  const lastZ = Math.abs((transferSizes[transferSizes.length - 1] - mean) / std);

  console.log(`   Normal transfers avg: ${(mean / 1000).toFixed(0)}KB`);
  console.log(`   Anomalous transfer:   ${(524288000 / 1024 / 1024).toFixed(0)}MB`);
  console.log(`   Z-Score:              ${lastZ.toFixed(1)} (threshold: 3.0)`);
  console.log(`   Result:               ${lastZ > 3 ? 'ANOMALY DETECTED' : 'Normal'}\n`);
}

simulateExfiltration().catch(console.error);
