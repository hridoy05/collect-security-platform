require('dotenv').config();
const bcrypt = require('bcryptjs');
const prisma = require('../config/prismaClient');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hoursAgo(h) {
  return new Date(Date.now() - h * 60 * 60 * 1000);
}

function daysFromNow(d) {
  return new Date(Date.now() + d * 24 * 60 * 60 * 1000);
}

function uid(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
}

// ─── Seed ────────────────────────────────────────────────────────────────────

async function seed() {
  console.log('🌱  Seeding database...\n');

  // ── 1. Users ──────────────────────────────────────────────────────────────
  const passwordHash = await bcrypt.hash('Admin@123', 12);

  await prisma.user.upsert({
    where:  { email: 'admin@connect.com' },
    update: {},
    create: { email: 'admin@connect.com', password: passwordHash, role: 'admin',   fullName: 'Connect Admin' }
  });
  await prisma.user.upsert({
    where:  { email: 'analyst@connect.com' },
    update: {},
    create: { email: 'analyst@connect.com', password: passwordHash, role: 'analyst', fullName: 'Security Analyst' }
  });
  console.log('✅  Users seeded (admin@connect.com / analyst@connect.com  pw: Admin@123)');

  // ── 2. Crypto Assets (CBOM) ───────────────────────────────────────────────
  const cryptoAssets = [
    // RED — critical
    { assetId: 'CBOM-001', assetType: 'tls_certificate', algorithm: 'RSA',        keyLength: 1024,  systemName: 'Legacy Payment Gateway',    environment: 'production',  ownerTeam: 'infra',    quantumSafe: false, riskRating: 'red',   expiryDate: daysFromNow(12),  daysToExpiry: 12,  issues: 'Short key length; quantum-vulnerable; expiring soon', rotationPolicy: 'annual' },
    { assetId: 'CBOM-002', assetType: 'signing_key',     algorithm: 'DSA',        keyLength: 1024,  systemName: 'Transaction Signing Service', environment: 'production',  ownerTeam: 'backend',  quantumSafe: false, riskRating: 'red',   expiryDate: daysFromNow(-5),  daysToExpiry: -5,  issues: 'Expired; DSA deprecated; quantum-vulnerable',         rotationPolicy: 'manual' },
    { assetId: 'CBOM-003', assetType: 'tls_certificate', algorithm: 'MD5',        keyLength: null,  systemName: 'Internal Admin Portal',       environment: 'production',  ownerTeam: 'devops',   quantumSafe: false, riskRating: 'red',   expiryDate: daysFromNow(3),   daysToExpiry: 3,   issues: 'MD5 broken; expiring in 3 days',                      rotationPolicy: 'manual' },
    { assetId: 'CBOM-004', assetType: 'api_key',         algorithm: 'RSA',        keyLength: 1024,  systemName: 'Mobile Banking API',          environment: 'production',  ownerTeam: 'mobile',   quantumSafe: false, riskRating: 'red',   expiryDate: daysFromNow(20),  daysToExpiry: 20,  issues: 'RSA-1024 too short; quantum-vulnerable',              rotationPolicy: 'quarterly' },
    // AMBER — elevated
    { assetId: 'CBOM-005', assetType: 'tls_certificate', algorithm: 'RSA',        keyLength: 2048,  systemName: 'Customer Portal',             environment: 'production',  ownerTeam: 'frontend', quantumSafe: false, riskRating: 'amber', expiryDate: daysFromNow(45),  daysToExpiry: 45,  issues: 'Quantum-vulnerable; rotation overdue',                rotationPolicy: 'annual' },
    { assetId: 'CBOM-006', assetType: 'symmetric_key',   algorithm: 'AES',        keyLength: 128,   systemName: 'Data Encryption Service',     environment: 'staging',     ownerTeam: 'backend',  quantumSafe: false, riskRating: 'amber', expiryDate: daysFromNow(90),  daysToExpiry: 90,  issues: 'AES-128; consider AES-256',                           rotationPolicy: 'quarterly' },
    { assetId: 'CBOM-007', assetType: 'signing_key',     algorithm: 'ECDSA',      keyLength: 256,   systemName: 'JWT Auth Service',            environment: 'production',  ownerTeam: 'auth',     quantumSafe: false, riskRating: 'amber', expiryDate: daysFromNow(60),  daysToExpiry: 60,  issues: 'ECDSA quantum-vulnerable; plan migration',            rotationPolicy: 'semi-annual' },
    { assetId: 'CBOM-008', assetType: 'tls_certificate', algorithm: 'RSA',        keyLength: 2048,  systemName: 'Reporting Engine',            environment: 'staging',     ownerTeam: 'data',     quantumSafe: false, riskRating: 'amber', expiryDate: daysFromNow(28),  daysToExpiry: 28,  issues: 'Expiring soon; quantum-vulnerable',                   rotationPolicy: 'annual' },
    // GREEN — safe
    { assetId: 'CBOM-009', assetType: 'symmetric_key',   algorithm: 'AES',        keyLength: 256,   systemName: 'Card Data Vault',             environment: 'production',  ownerTeam: 'security', quantumSafe: true,  riskRating: 'green', expiryDate: daysFromNow(365), daysToExpiry: 365, issues: null,                                                  rotationPolicy: 'quarterly' },
    { assetId: 'CBOM-010', assetType: 'tls_certificate', algorithm: 'CRYSTALS-Kyber', keyLength: 768, systemName: 'Post-Quantum API Gateway',  environment: 'production',  ownerTeam: 'infra',    quantumSafe: true,  riskRating: 'green', expiryDate: daysFromNow(700), daysToExpiry: 700, issues: null,                                                  rotationPolicy: 'annual' },
    { assetId: 'CBOM-011', assetType: 'signing_key',     algorithm: 'CRYSTALS-Dilithium', keyLength: 2, systemName: 'Code Signing Pipeline', environment: 'production',  ownerTeam: 'devops',   quantumSafe: true,  riskRating: 'green', expiryDate: daysFromNow(500), daysToExpiry: 500, issues: null,                                                  rotationPolicy: 'annual' },
    { assetId: 'CBOM-012', assetType: 'symmetric_key',   algorithm: 'AES',        keyLength: 256,   systemName: 'Audit Log Encryption',        environment: 'production',  ownerTeam: 'security', quantumSafe: true,  riskRating: 'green', expiryDate: daysFromNow(180), daysToExpiry: 180, issues: null,                                                  rotationPolicy: 'monthly' },
  ];

  for (const asset of cryptoAssets) {
    await prisma.cryptoAsset.upsert({
      where:  { assetId: asset.assetId },
      update: asset,
      create: asset
    });
  }
  console.log(`✅  Crypto assets seeded (${cryptoAssets.length} assets: 4 red, 4 amber, 4 green)`);

  // ── 3. Security Alerts (spread over last 24 h for chart data) ─────────────
  const alertDefs = [
    // CRITICAL
    { title: 'Brute Force Attack — Payment API',         description: 'Over 500 failed login attempts from single IP targeting admin accounts', severity: 'critical', sourceIp: '45.33.32.156',  mitreTactic: 'Credential Access',  mitreTechnique: 'T1110 — Brute Force',                    alertScore: 97, hoursBack: 1  },
    { title: 'Credential Stuffing Detected',              description: '2,400 login attempts with breached credentials across 180 accounts',     severity: 'critical', sourceIp: '185.220.101.45',mitreTactic: 'Credential Access',  mitreTechnique: 'T1110.004 — Credential Stuffing',        alertScore: 95, hoursBack: 3  },
    { title: 'DNS Tunneling — Data Exfiltration',         description: 'High-entropy DNS queries detected carrying encoded payload to C2 server', severity: 'critical', sourceIp: '10.0.0.45',    mitreTactic: 'Exfiltration',       mitreTechnique: 'T1048.003 — Exfiltration Over DNS',      alertScore: 93, hoursBack: 5  },
    { title: 'TLS Certificate Expired — Admin Portal',    description: 'MD5-signed certificate expired 5 days ago; active MITM risk',           severity: 'critical', sourceIp: null,            mitreTactic: 'Defense Evasion',    mitreTechnique: 'T1553.004 — Install Root Certificate',   alertScore: 91, hoursBack: 2  },
    { title: 'Privilege Escalation — Internal Host',      description: 'Analyst account escalated to root on db-primary-01 via sudo exploit',   severity: 'critical', sourceIp: '192.168.1.45',  mitreTactic: 'Privilege Escalation',mitreTechnique: 'T1068 — Exploitation for Privilege Esc', alertScore: 98, hoursBack: 7  },
    // HIGH
    { title: 'Port Scan — Firewall Perimeter',            description: 'Sequential SYN scan across 65,535 ports from external IP',              severity: 'high',     sourceIp: '203.0.113.42',  mitreTactic: 'Discovery',          mitreTechnique: 'T1046 — Network Service Scanning',       alertScore: 78, hoursBack: 4  },
    { title: 'Brute Force — SSH Service',                 description: '340 failed SSH authentication attempts over 20-minute window',          severity: 'high',     sourceIp: '91.108.4.13',   mitreTactic: 'Credential Access',  mitreTechnique: 'T1110.001 — Password Guessing',          alertScore: 82, hoursBack: 6  },
    { title: 'Lateral Movement Detected',                 description: 'Compromised service account accessed 12 internal hosts via WMI',        severity: 'high',     sourceIp: '192.168.1.112', mitreTactic: 'Lateral Movement',   mitreTechnique: 'T1021 — Remote Services',                alertScore: 85, hoursBack: 8  },
    { title: 'Malware C2 Beacon Detected',                description: 'Periodic beacon to known C2 IP at 60-second intervals',                 severity: 'high',     sourceIp: '10.0.0.67',    mitreTactic: 'Command and Control',mitreTechnique: 'T1071.001 — Web Protocols',              alertScore: 88, hoursBack: 9  },
    { title: 'Anomalous Data Transfer — Exfil Risk',      description: '4.2 GB transferred to external IP outside business hours',              severity: 'high',     sourceIp: '10.0.0.89',    mitreTactic: 'Exfiltration',       mitreTechnique: 'T1048 — Exfiltration Over Alternative Protocol', alertScore: 80, hoursBack: 11 },
    { title: 'Persistence Mechanism Installed',           description: 'New cron job and startup script detected on payment-processor-02',      severity: 'high',     sourceIp: '192.168.1.201', mitreTactic: 'Persistence',        mitreTechnique: 'T1053.005 — Scheduled Task/Job',         alertScore: 76, hoursBack: 13 },
    // MEDIUM
    { title: 'Port Scan — Internal Segment',              description: 'Internal host performing port scan on DB subnet',                        severity: 'medium',   sourceIp: '192.168.2.45',  mitreTactic: 'Discovery',          mitreTechnique: 'T1046 — Network Service Scanning',       alertScore: 55, hoursBack: 10 },
    { title: 'Suspicious PowerShell Execution',           description: 'Encoded PowerShell command executed on workstation WS-042',             severity: 'medium',   sourceIp: '192.168.3.42',  mitreTactic: 'Execution',          mitreTechnique: 'T1059.001 — PowerShell',                 alertScore: 62, hoursBack: 12 },
    { title: 'Account Created Outside Business Hours',    description: 'New admin account created at 02:14 AM with no change-ticket reference', severity: 'medium',   sourceIp: '192.168.1.5',   mitreTactic: 'Persistence',        mitreTechnique: 'T1136.001 — Create Local Account',       alertScore: 58, hoursBack: 14 },
    { title: 'TLS Downgrade Attempt',                     description: 'Client forced TLS 1.0 handshake on PCI-scoped endpoint',                severity: 'medium',   sourceIp: '203.0.113.9',   mitreTactic: 'Defense Evasion',    mitreTechnique: 'T1562 — Impair Defenses',                alertScore: 60, hoursBack: 16 },
    { title: 'DNS Query — Known Malware Domain',          description: 'Internal host queried blacklisted domain associated with Emotet C2',     severity: 'medium',   sourceIp: '10.0.0.23',    mitreTactic: 'Command and Control',mitreTechnique: 'T1071.004 — DNS',                        alertScore: 65, hoursBack: 15 },
    // LOW
    { title: 'Failed Login — Analyst Account',            description: '5 consecutive failed logins from unusual location (Germany)',            severity: 'low',      sourceIp: '91.189.89.1',   mitreTactic: 'Initial Access',     mitreTechnique: 'T1078 — Valid Accounts',                 alertScore: 30, hoursBack: 17 },
    { title: 'Self-Signed Certificate Detected',          description: 'Internal service using self-signed cert — not in approved CBOM registry', severity: 'low',    sourceIp: null,            mitreTactic: 'Defense Evasion',    mitreTechnique: 'T1553 — Subvert Trust Controls',         alertScore: 28, hoursBack: 18 },
    { title: 'Weak Cipher Suite Negotiated',              description: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA negotiated on legacy endpoint',           severity: 'low',      sourceIp: '10.10.0.5',    mitreTactic: 'Defense Evasion',    mitreTechnique: 'T1040 — Network Sniffing',               alertScore: 35, hoursBack: 20 },
    { title: 'Outdated Software — OpenSSL 1.0.2',         description: 'Dependency scan found EOL OpenSSL 1.0.2 on payment-worker-03',          severity: 'low',      sourceIp: null,            mitreTactic: 'Initial Access',     mitreTechnique: 'T1190 — Exploit Public-Facing Application', alertScore: 25, hoursBack: 22 },
  ];

  let alertCount = 0;
  for (const def of alertDefs) {
    const alertId = uid('ALT');
    const created = hoursAgo(def.hoursBack);
    await prisma.securityAlert.create({
      data: {
        alertId,
        title:          def.title,
        description:    def.description,
        severity:       def.severity,
        status:         def.hoursBack > 12 ? 'open' : (def.severity === 'low' ? 'resolved' : 'open'),
        sourceType:     'siem',
        sourceIp:       def.sourceIp || undefined,
        mitreTactic:    def.mitreTactic,
        mitreTechnique: def.mitreTechnique,
        alertScore:     def.alertScore,
        rawEvent:       {},
        threatIntel:    {},
        createdAt:      created,
        updatedAt:      created,
      }
    });
    alertCount++;
  }
  console.log(`✅  Security alerts seeded (${alertCount} alerts across last 24 h)`);

  // ── 4. Threat Indicators (IOCs) ───────────────────────────────────────────
  const iocs = [
    { iocType: 'ip',     iocValue: '45.33.32.156',          threatActor: 'FIN7',   campaign: 'Operation Night Fury', confidence: 95, severity: 'critical', source: 'MISP', tags: ['apt','financial','ransomware'], firstSeen: hoursAgo(720), lastSeen: hoursAgo(1) },
    { iocType: 'ip',     iocValue: '185.220.101.45',         threatActor: 'APT29',  campaign: 'Cozy Bear',            confidence: 90, severity: 'critical', source: 'AlienVault', tags: ['apt','state-sponsored'], firstSeen: hoursAgo(360), lastSeen: hoursAgo(3) },
    { iocType: 'ip',     iocValue: '91.108.4.13',            threatActor: 'Lazarus',campaign: 'Operation AppleJeus',  confidence: 88, severity: 'high',     source: 'FS-ISAC', tags: ['apt','crypto','dprk'],      firstSeen: hoursAgo(200), lastSeen: hoursAgo(6) },
    { iocType: 'ip',     iocValue: '203.0.113.42',           threatActor: null,     campaign: null,                   confidence: 60, severity: 'medium',   source: 'Internal', tags: ['scanner'],                  firstSeen: hoursAgo(48),  lastSeen: hoursAgo(4) },
    { iocType: 'domain', iocValue: 'update.cdn.attacker.io', threatActor: 'FIN7',   campaign: 'Operation Night Fury', confidence: 92, severity: 'critical', source: 'MISP', tags: ['c2','apt'],                   firstSeen: hoursAgo(500), lastSeen: hoursAgo(5) },
    { iocType: 'domain', iocValue: 'login.paybd-secure.com', threatActor: null,     campaign: 'PayBD Phishing',       confidence: 85, severity: 'high',     source: 'PhishTank', tags: ['phishing','typosquatting'],firstSeen: hoursAgo(100), lastSeen: hoursAgo(2) },
    { iocType: 'domain', iocValue: 'cdn.malware.xyz',         threatActor: 'UNC2452',campaign: 'SolarWinds Follow-On',confidence: 80, severity: 'high',     source: 'CISA', tags: ['c2','supply-chain'],           firstSeen: hoursAgo(300), lastSeen: hoursAgo(8) },
    { iocType: 'domain', iocValue: 'evil.exfil-dns.net',      threatActor: null,     campaign: null,                   confidence: 70, severity: 'high',     source: 'Internal-ML', tags: ['dns-tunnel','exfil'],    firstSeen: hoursAgo(24),  lastSeen: hoursAgo(5) },
    { iocType: 'hash',   iocValue: 'd41d8cd98f00b204e9800998ecf8427e', threatActor: 'FIN7', campaign: 'Operation Night Fury', confidence: 99, severity: 'critical', source: 'VirusTotal', tags: ['malware','ransomware','md5'], firstSeen: hoursAgo(72), lastSeen: hoursAgo(10) },
    { iocType: 'hash',   iocValue: 'a3f5c1b2e4d87f9012345678abcdef01', threatActor: 'Lazarus', campaign: null,          confidence: 88, severity: 'high',     source: 'MISP', tags: ['dropper','dprk'],              firstSeen: hoursAgo(168), lastSeen: hoursAgo(20) },
    { iocType: 'email',  iocValue: 'noreply@paybd-secure.com',threatActor: null,     campaign: 'PayBD Phishing',       confidence: 78, severity: 'medium',   source: 'PhishTank', tags: ['phishing'],                firstSeen: hoursAgo(50),  lastSeen: hoursAgo(12) },
    { iocType: 'url',    iocValue: 'http://45.33.32.156/payload.exe', threatActor: 'FIN7', campaign: 'Operation Night Fury', confidence: 96, severity: 'critical', source: 'MISP', tags: ['payload','apt'], firstSeen: hoursAgo(400), lastSeen: hoursAgo(1) },
  ];

  await prisma.threatIndicator.createMany({ data: iocs, skipDuplicates: true });
  console.log(`✅  Threat indicators seeded (${iocs.length} IOCs)`);

  // ── 5. CVE Tracking ───────────────────────────────────────────────────────
  const cves = [
    { cveId: 'CVE-2023-44487', cvssScore: 7.5,  cvssSeverity: 'high',     epssScore: 0.9731, isKev: true,  description: 'HTTP/2 Rapid Reset DDoS vulnerability (NGINX, Apache, etc.)',               affectedProduct: 'Multiple HTTP/2 servers',          patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-3094',  cvssScore: 10.0, cvssSeverity: 'critical', epssScore: 0.8921, isKev: true,  description: 'XZ Utils backdoor allowing remote code execution via SSHD',                  affectedProduct: 'XZ Utils 5.6.0-5.6.1',             patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-4966',  cvssScore: 9.4,  cvssSeverity: 'critical', epssScore: 0.9533, isKev: true,  description: 'Citrix Bleed — session token leak in NetScaler ADC/Gateway',                   affectedProduct: 'Citrix NetScaler ADC/Gateway',      patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-21413', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.7814, isKev: true,  description: 'Microsoft Outlook RCE via Moniker Link (MHT file)',                           affectedProduct: 'Microsoft Outlook',                 patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-20198', cvssScore: 10.0, cvssSeverity: 'critical', epssScore: 0.9755, isKev: true,  description: 'Cisco IOS XE Web UI privilege escalation — zero-day',                         affectedProduct: 'Cisco IOS XE',                      patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-1709',  cvssScore: 10.0, cvssSeverity: 'critical', epssScore: 0.9620, isKev: true,  description: 'ConnectWise ScreenConnect auth bypass allowing full system access',            affectedProduct: 'ConnectWise ScreenConnect < 23.9.8',patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-46604', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.9812, isKev: true,  description: 'Apache ActiveMQ RCE — ClassInfo exploit used by ransomware groups',           affectedProduct: 'Apache ActiveMQ < 5.15.16',          patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-6387',  cvssScore: 8.1,  cvssSeverity: 'high',     epssScore: 0.4512, isKev: false, description: 'OpenSSH regreSSHion — race condition RCE (unauthenticated)',                   affectedProduct: 'OpenSSH 8.5–9.7',                   patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-42793', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.9432, isKev: true,  description: 'JetBrains TeamCity auth bypass — supply chain risk',                          affectedProduct: 'JetBrains TeamCity < 2023.05.4',    patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-23113', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.8933, isKev: true,  description: 'FortiOS format string vulnerability — unauthenticated RCE',                   affectedProduct: 'Fortinet FortiOS 7.0–7.4',          patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-36884', cvssScore: 8.3,  cvssSeverity: 'high',     epssScore: 0.6721, isKev: false, description: 'Microsoft Office HTML injection RCE via crafted document',                    affectedProduct: 'Microsoft Office 2019/2021/365',    patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2024-0519',  cvssScore: 8.8,  cvssSeverity: 'high',     epssScore: 0.3411, isKev: false, description: 'Chrome V8 OOB memory access — actively exploited in the wild',               affectedProduct: 'Google Chrome < 120.0.6099.129',    patchAvailable: true,  status: 'open' },
    { cveId: 'CVE-2023-22515', cvssScore: 10.0, cvssSeverity: 'critical', epssScore: 0.9601, isKev: true,  description: 'Atlassian Confluence broken access control — admin account creation',         affectedProduct: 'Atlassian Confluence DC/Server',    patchAvailable: true,  status: 'patched', patchedAt: hoursAgo(72) },
    { cveId: 'CVE-2023-27997', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.9211, isKev: true,  description: 'FortiGate SSL VPN heap overflow — pre-auth RCE',                             affectedProduct: 'Fortinet FortiOS SSL-VPN',          patchAvailable: true,  status: 'patched', patchedAt: hoursAgo(120) },
    { cveId: 'CVE-2024-27198', cvssScore: 9.8,  cvssSeverity: 'critical', epssScore: 0.9010, isKev: false, description: 'JetBrains TeamCity auth bypass (2024 variant) — CI/CD supply chain risk',    affectedProduct: 'JetBrains TeamCity < 2023.11.4',    patchAvailable: false, status: 'open' },
  ];

  for (const cve of cves) {
    await prisma.cveTracking.upsert({
      where:  { cveId: cve.cveId },
      update: cve,
      create: cve
    });
  }
  console.log(`✅  CVEs seeded (${cves.length} CVEs: ${cves.filter(c => c.isKev && c.status === 'open').length} KEV open)`);

  // ── 6. ML Anomalies ───────────────────────────────────────────────────────
  const mlAnomalies = [
    { modelType: 'dns_tunneling',    entityType: 'dns_query',  entityValue: 'aGVsbG8gd29ybGQ.attacker.com',          anomalyScore: 0.9312, threshold: 0.5, isAnomaly: true,  alertCreated: true,  description: 'High-entropy DNS query — Shannon entropy 4.5',          createdAt: hoursAgo(5) },
    { modelType: 'dns_tunneling',    entityType: 'dns_query',  entityValue: 'dGhpcyBpcyBzdG9sZW4gZGF0YQ.evil.net',   anomalyScore: 0.8841, threshold: 0.5, isAnomaly: true,  alertCreated: true,  description: 'DNS tunnel carrying base64-encoded payload',             createdAt: hoursAgo(5) },
    { modelType: 'dns_tunneling',    entityType: 'dns_query',  entityValue: 'cGF5bWVudCBkYXRh.cdn.malware.xyz',       anomalyScore: 0.8203, threshold: 0.5, isAnomaly: true,  alertCreated: false, description: 'Suspected DNS exfiltration — payment data pattern',     createdAt: hoursAgo(6) },
    { modelType: 'ueba',             entityType: 'user',       entityValue: 'analyst@connect.com',                    anomalyScore: 0.7711, threshold: 0.6, isAnomaly: true,  alertCreated: true,  description: 'Login from new country (DE) at unusual hour (02:00)',   createdAt: hoursAgo(17) },
    { modelType: 'ueba',             entityType: 'user',       entityValue: 'svc-payment@paybd.internal',             anomalyScore: 0.8900, threshold: 0.6, isAnomaly: true,  alertCreated: true,  description: 'Service account interactive login — policy violation',  createdAt: hoursAgo(13) },
    { modelType: 'isolation_forest', entityType: 'network',    entityValue: '192.168.1.45',                           anomalyScore: 0.9102, threshold: 0.7, isAnomaly: true,  alertCreated: true,  description: 'Traffic volume 18× baseline — possible data staging',   createdAt: hoursAgo(11) },
    { modelType: 'isolation_forest', entityType: 'network',    entityValue: '10.0.0.67',                              anomalyScore: 0.7422, threshold: 0.7, isAnomaly: true,  alertCreated: false, description: 'Beacon pattern detected — 60s interval to external IP', createdAt: hoursAgo(9) },
    { modelType: 'zscore',           entityType: 'metric',     entityValue: 'auth_failures_per_min',                  anomalyScore: 0.9800, threshold: 0.8, isAnomaly: true,  alertCreated: true,  description: 'z-score 7.4 — auth failure rate 7.4σ above baseline',  createdAt: hoursAgo(3) },
    { modelType: 'zscore',           entityType: 'metric',     entityValue: 'bytes_out_per_hour',                     anomalyScore: 0.8621, threshold: 0.8, isAnomaly: true,  alertCreated: true,  description: 'z-score 5.9 — outbound transfer spike',                createdAt: hoursAgo(11) },
    { modelType: 'isolation_forest', entityType: 'api',        entityValue: '/api/payments/transfer',                 anomalyScore: 0.6100, threshold: 0.7, isAnomaly: false, alertCreated: false, description: 'Mild request rate increase — within normal range',      createdAt: hoursAgo(4) },
  ];

  await prisma.mlAnomaly.createMany({ data: mlAnomalies, skipDuplicates: false });
  console.log(`✅  ML anomalies seeded (${mlAnomalies.length} records)`);

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('\n🎉  Full seed complete.\n');
  console.log('   Credentials:   admin@connect.com / analyst@connect.com  →  Admin@123');
  console.log('   Crypto assets: 4 red · 4 amber · 4 green');
  console.log(`   Alerts:        ${alertCount} across last 24 h (critical/high/medium/low)`);
  console.log(`   IOCs:          ${iocs.length} threat indicators`);
  console.log(`   CVEs:          ${cves.length} (${cves.filter(c => c.isKev && c.status === 'open').length} KEV open)`);
  console.log(`   ML anomalies:  ${mlAnomalies.length}`);
}

seed()
  .catch(err => { console.error('Seed failed:', err); process.exit(1); })
  .finally(() => prisma.$disconnect());
