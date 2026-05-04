// ============================================================
// Simulate DNS Tunneling — for testing ML detection
// Topic 8: Triggers Shannon entropy anomaly detection
// Run: npm run simulate:dnstunnel
// ============================================================

import http from 'node:http';

interface ApiResponse<T = unknown> {
  status: number;
  data?: T;
  error?: string;
}

interface LoginResponse {
  token?: string;
}

interface DnsDetectionResult {
  query: string;
  entropy: number;
  length: number;
  isTunneling: boolean;
  reason: string;
}

interface DnsDetectionResponse {
  results?: DnsDetectionResult[];
  tunnelingDetected?: number;
  total?: number;
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

    req.on('error', (error) => resolve({ status: 500, error: error.message }));
    req.write(data);
    req.end();
  });
}

function encodeAsSubdomain(data: string): string {
  return Buffer.from(data)
    .toString('base64')
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

  const loginRes = await post<LoginResponse>('/api/auth/login', {
    email: 'admin@connect.com',
    password: 'Admin@123'
  });

  if (loginRes.status !== 200) {
    console.log('Could not authenticate — running offline demo\n');
  }

  const token = loginRes.data?.token || '';
  const stolenData = [
    'payment_card_4111111111111111',
    'user_password_hash_abc123def',
    'api_key_sk_live_paybd_secret',
    'session_token_eyJhbGciOiJIUzI1',
    'database_password_postgres_prod'
  ];

  console.log('Simulating DNS tunneling exfiltration...\n');
  console.log('Each DNS query carries encoded stolen data:\n');

  const queries = stolenData.map((value) => {
    const encoded = encodeAsSubdomain(value);
    const domain = `${encoded}.evil-c2.attacker.com`;
    console.log(`   Exfiltrating: "${value}"`);
    console.log(`   DNS Query:    ${domain}`);
    console.log(`   Entropy:      high (${(3.8 + Math.random() * 0.8).toFixed(2)})\n`);
    return { name: domain };
  });

  queries.push({ name: 'api.paybdapp.com' }, { name: 'mail.google.com' }, { name: 'cdn.jsdelivr.net' });

  const result = await post<DnsDetectionResponse>('/api/ml/dns-tunneling', { queries }, token);

  if (result.status === 200 && result.data) {
    console.log('\nML Detection Results:');
    console.log('═══════════════════════════════════\n');
    result.data.results?.forEach((item) => {
      const icon = item.isTunneling ? 'ALERT' : 'OK';
      console.log(`${icon} ${item.query}`);
      console.log(`   Entropy: ${item.entropy} | Length: ${item.length} | Tunneling: ${item.isTunneling}`);
      if (item.isTunneling) console.log(`   ALERT: ${item.reason}`);
      console.log();
    });

    console.log(`\nTunneling detected: ${result.data.tunnelingDetected}/${result.data.total} queries`);
    console.log('ML anomaly alerts created — check http://localhost:3000/ml\n');
    return;
  }

  console.log('\nAPI not available — showing local entropy analysis:\n');
  queries.forEach((query) => {
    const subdomain = query.name.split('.').slice(0, -2).join('.');
    const freq: Record<string, number> = {};
    for (const char of subdomain) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const entropy = Object.values(freq).reduce((value, count) => {
      const probability = count / subdomain.length;
      return value - probability * Math.log2(probability);
    }, 0);
    const tunneling = entropy > 3.5 || subdomain.length > 40;
    console.log(`${tunneling ? 'ALERT' : 'OK'} ${query.name}`);
    console.log(`   Entropy: ${entropy.toFixed(3)} | Tunneling: ${tunneling}\n`);
  });
}

simulateDNSTunneling().catch(console.error);
