import { useEffect, useState } from 'react';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Input, Textarea } from '../components/ui/Input';
import { StatCard } from '../components/ui/StatCard';
import { Tabs } from '../components/ui/Tabs';
import { Table, Thead, Th, Tr, Td } from '../components/ui/Table';
import { api } from '../utils/api';

// ── THREAT INTEL ─────────────────────────────────────────────
export function ThreatIntel() {
  const [iocs, setIocs] = useState([]);
  const [cves, setCves] = useState([]);
  const [lookupVal, setLookupVal] = useState('');
  const [lookupType, setLookupType] = useState('ip');
  const [lookupResult, setLookupResult] = useState(null);

  useEffect(() => {
    api.get('/api/threat-intel/iocs').then(d => setIocs(Array.isArray(d) ? d : d?.iocs || [])).catch(() => {});
    api.get('/api/threat-intel/cves').then(d => setCves(Array.isArray(d) ? d : d?.cves || [])).catch(() => {});
  }, []);

  const lookup = async () => {
    if (!lookupVal.trim()) return;
    try {
      const res = await api.post('/api/threat-intel/lookup', { indicator: lookupVal, type: lookupType });
      setLookupResult(res);
    } catch {
      setLookupResult({ found: false });
    }
  };

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="mb-8">
        <h1 className="font-mono uppercase tracking-ui text-2xl text-white">Threat Intelligence</h1>
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">IOC & CVE Enrichment · Topic 6</p>
      </div>

      <Card className="mb-8">
        <CardTitle className="mb-4">IOC Lookup</CardTitle>
        <CardContent>
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <Input value={lookupVal} onChange={e => setLookupVal(e.target.value)} placeholder="IP address, domain, or hash…" onKeyDown={e => e.key === 'Enter' && lookup()} />
            </div>
            <select value={lookupType} onChange={e => setLookupType(e.target.value)}
              className="bg-black border border-[#999]/40 rounded px-3 py-2 text-white font-mono text-xs focus:border-white focus:outline-none">
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
            <Button variant="secondary" onClick={lookup}>Lookup</Button>
          </div>
          {lookupResult && (
            <div className={`mt-4 p-3 rounded border font-mono text-xs ${lookupResult.found ? 'border-[#fc4d4d]/40 text-[#fc4d4d]' : 'border-[#48bb78]/40 text-[#48bb78]'}`}>
              {lookupResult.found
                ? <><div className="uppercase tracking-ui mb-1">Malicious — {lookupResult.intel?.threat_actor}</div><div className="text-[#999]">Campaign: {lookupResult.intel?.campaign}</div></>
                : <div className="uppercase tracking-ui">Not found in threat database</div>}
            </div>
          )}
        </CardContent>
      </Card>

      <Tabs tabs={[{ key: 'iocs', label: 'IOCs' }, { key: 'cves', label: 'CVEs' }]}>
        {(active) => (
          <>
            {active === 'iocs' && (
              <Card className="p-0">
                <Table>
                  <Thead><tr>{['Type', 'Indicator', 'Threat Actor', 'Campaign', 'Confidence', 'Severity', 'Tags'].map(h => <Th key={h}>{h}</Th>)}</tr></Thead>
                  <tbody>
                    {iocs.map((ioc, i) => (
                      <Tr key={i}>
                        <Td><Badge>{ioc.ioc_type || ioc.iocType}</Badge></Td>
                        <Td className="font-mono text-xs text-[#999] max-w-[200px] truncate">{ioc.ioc_value || ioc.iocValue}</Td>
                        <Td className="text-xs">{ioc.threat_actor || ioc.threatActor || '—'}</Td>
                        <Td className="text-xs text-[#999]">{ioc.campaign || '—'}</Td>
                        <Td>
                          <div className="flex items-center gap-2">
                            <div className="h-px w-16 bg-[#999]/20"><div className="h-full bg-[#63b3ed]" style={{ width: `${ioc.confidence || 0}%` }} /></div>
                            <span className="font-mono text-[10px] text-[#999]">{ioc.confidence}%</span>
                          </div>
                        </Td>
                        <Td><Badge variant={ioc.severity === 'critical' ? 'red' : ioc.severity === 'high' ? 'amber' : 'default'}>{ioc.severity}</Badge></Td>
                        <Td><div className="flex flex-wrap gap-1">{(ioc.tags || []).map(t => <Badge key={t} variant="blue">{t}</Badge>)}</div></Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </Card>
            )}
            {active === 'cves' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {cves.map((cve, i) => {
                  const isKev = cve.is_kev || cve.isKev;
                  const cvss = cve.cvss_score || cve.cvssScore;
                  const hasPatch = cve.patch_available || cve.patchAvailable;
                  return (
                    <Card key={i} className={isKev ? 'border-[#fc4d4d]/40' : ''}>
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <div className="font-mono uppercase tracking-ui text-xs text-white">{cve.cve_id || cve.cveId}</div>
                          {isKev && <Badge variant="red" className="mt-1">KEV · Actively Exploited</Badge>}
                        </div>
                        <div className="text-right">
                          <div className="font-mono text-lg" style={{ color: cvss >= 9 ? '#fc4d4d' : cvss >= 7 ? '#f6ad55' : '#48bb78' }}>{cvss}</div>
                          <div className="font-mono uppercase tracking-ui text-[9px] text-[#999]">CVSS</div>
                        </div>
                      </div>
                      <p className="text-xs text-[#999] leading-relaxed mb-3">{cve.description}</p>
                      <div className="flex gap-2 flex-wrap">
                        <Badge>{cve.affected_product || cve.affectedProduct}</Badge>
                        <Badge variant={hasPatch ? 'green' : 'red'}>{hasPatch ? 'Patch Available' : 'No Patch'}</Badge>
                        <Badge variant={cve.status === 'open' ? 'amber' : 'green'}>{cve.status}</Badge>
                      </div>
                    </Card>
                  );
                })}
              </div>
            )}
          </>
        )}
      </Tabs>
    </div>
  );
}

// ── ML DETECTION ──────────────────────────────────────────────
function calcEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((s, f) => { const p = f / str.length; return s + p * Math.log2(p); }, 0);
}
function localZ(values) {
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const std = Math.sqrt(values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length) || 1;
  return values.map(v => ({ value: v, zscore: ((v - mean) / std).toFixed(2), isAnomaly: Math.abs((v - mean) / std) > 3 }));
}

export function MLDetection() {
  const [dnsInput, setDnsInput] = useState('x1k3m2.update.microsoft.com\nbase64encoded.malware.xyz\nnormal.google.com');
  const [dnsResults, setDnsResults] = useState([]);
  const [zInput, setZInput] = useState('100,102,98,101,99,200,103,97');
  const [zResults, setZResults] = useState([]);
  const [anomalies, setAnomalies] = useState([]);

  useEffect(() => {
    api.get('/api/ml/anomalies').then(d => setAnomalies(Array.isArray(d) ? d : d?.anomalies || [])).catch(() => {});
  }, []);

  const analyzeDns = async () => {
    const queries = dnsInput.split('\n').filter(Boolean).map(q => ({ name: q.trim() }));
    try {
      const res = await api.post('/api/ml/dns-tunneling', { queries });
      setDnsResults(res?.results || queries.map(q => {
        const e = calcEntropy(q.name.split('.')[0]);
        return { query: q.name, entropy: e.toFixed(2), anomalyScore: (e / 5).toFixed(3), isTunneling: e > 3.5 };
      }));
    } catch {
      setDnsResults(queries.map(q => {
        const e = calcEntropy(q.name.split('.')[0]);
        return { query: q.name, entropy: e.toFixed(2), anomalyScore: (e / 5).toFixed(3), isTunneling: e > 3.5 };
      }));
    }
  };

  const analyzeZ = async () => {
    const values = zInput.split(',').map(Number).filter(n => !isNaN(n));
    try {
      const res = await api.post('/api/ml/zscore', { values });
      setZResults(res?.results || localZ(values));
    } catch {
      setZResults(localZ(values));
    }
  };

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="mb-8">
        <h1 className="font-mono uppercase tracking-ui text-2xl text-white">ML Anomaly Detection</h1>
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">Z-Score · Isolation Forest · UEBA · Topic 8</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardTitle className="mb-4">DNS Tunneling Detection</CardTitle>
          <CardContent>
            <Textarea value={dnsInput} onChange={e => setDnsInput(e.target.value)} rows={4} placeholder="One DNS query per line…" className="mb-3" />
            <Button variant="secondary" onClick={analyzeDns}>Analyze DNS</Button>
            {dnsResults.length > 0 && (
              <div className="mt-4 flex flex-col gap-2">
                {dnsResults.map((r, i) => (
                  <div key={i} className="border border-[#999]/20 rounded p-3">
                    <div className="font-mono text-xs text-[#999] truncate mb-2">{r.query || r.name}</div>
                    <div className="flex gap-3 items-center flex-wrap">
                      <span className="font-mono text-[10px]">Entropy <span className="text-white">{r.entropy}</span></span>
                      <span className="font-mono text-[10px]">Score <span className="text-white">{r.anomalyScore}</span></span>
                      <Badge variant={r.isTunneling ? 'red' : 'green'}>{r.isTunneling ? '⚠ Tunneling' : '✓ Clean'}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardTitle className="mb-4">Z-Score Anomaly Detection</CardTitle>
          <CardContent>
            <Input value={zInput} onChange={e => setZInput(e.target.value)} placeholder="Comma-separated values…" className="mb-3" />
            <Button variant="secondary" onClick={analyzeZ}>Analyze</Button>
            {zResults.length > 0 && (
              <div className="mt-4 flex flex-col gap-2">
                {zResults.map((r, i) => (
                  <div key={i} className="flex items-center justify-between border border-[#999]/10 rounded px-3 py-2">
                    <span className="font-mono text-xs text-white">{r.value}</span>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[10px] text-[#999]">z = <span className="text-white">{r.zscore}</span></span>
                      <Badge variant={r.isAnomaly ? 'red' : 'green'}>{r.isAnomaly ? 'Anomaly' : 'Normal'}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardTitle className="mb-4">Recent ML Anomalies</CardTitle>
        <CardContent className="flex flex-col gap-3">
          {anomalies.length === 0 ? (
            <div className="text-center font-mono uppercase tracking-ui text-[10px] text-[#999] py-8">No anomalies detected</div>
          ) : anomalies.map((a, i) => (
            <div key={i} className="flex items-start gap-3 border-b border-[#999]/10 pb-3 last:border-0 last:pb-0">
              <div className="mt-1 w-2 h-2 rounded-full bg-[#fc4d4d] shrink-0 animate-pulse" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-mono text-xs text-white truncate">{a.entity_value || a.entityValue}</span>
                  <Badge variant="purple">{a.model_type || a.modelType}</Badge>
                </div>
                <div className="text-xs text-[#999]">{a.description}</div>
              </div>
              <div className="text-right shrink-0">
                <div className="font-mono text-sm text-[#fc4d4d]">{Math.round((a.anomaly_score || a.anomalyScore || 0) * 100)}%</div>
                <div className="font-mono uppercase tracking-ui text-[9px] text-[#999]">Score</div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ── NETWORK ───────────────────────────────────────────────────
const PROTOCOLS = [
  { name: 'HTTPS', pct: 68, count: '2.4M', color: '#48bb78' },
  { name: 'DNS',   pct: 23, count: '810K', color: '#63b3ed' },
  { name: 'HTTP',  pct: 6,  count: '211K', color: '#f6ad55' },
  { name: 'SSH',   pct: 1.2, count: '42K', color: '#9f7aea' },
  { name: 'Other', pct: 1.8, count: '63K', color: '#999' },
];
const TOP_IPS = [
  { ip: '45.155.205.1',   country: 'RU', count: '12,400', level: 'critical' },
  { ip: '192.168.1.105',  country: 'BD', count: '8,200',  level: 'normal' },
  { ip: '104.21.45.87',   country: 'US', count: '6,800',  level: 'normal' },
  { ip: '185.220.101.45', country: 'DE', count: '5,100',  level: 'high' },
  { ip: '10.0.0.254',     country: 'BD', count: '4,300',  level: 'normal' },
];
const DNS_ANOMALIES = [
  { domain: 'dGhpcyBpcyBhIHRlc3Q.evil.com',        entropy: '4.2', note: 'Base64 encoded subdomain' },
  { domain: 'aGVsbG8gd29ybGQ.c2.attacker.io',        entropy: '4.0', note: 'High-entropy subdomain chain' },
  { domain: 'eW91IGhhdmUgYmVlbg.cdn.malware.xyz', entropy: '3.8', note: 'Suspected DNS tunnel' },
];

export function Network() {
  return (
    <div className="p-8 max-w-[1400px]">
      <div className="mb-8">
        <h1 className="font-mono uppercase tracking-ui text-2xl text-white">Network Monitor</h1>
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">Protocol Analysis · DNS Anomalies · Topic 3</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardTitle className="mb-4">Protocol Distribution — 24h</CardTitle>
          <CardContent className="flex flex-col gap-4">
            {PROTOCOLS.map(p => (
              <div key={p.name}>
                <div className="flex justify-between mb-1">
                  <span className="font-mono uppercase tracking-ui text-[10px] text-[#999]">{p.name}</span>
                  <span className="font-mono text-[10px]" style={{ color: p.color }}>{p.pct}% · {p.count}</span>
                </div>
                <div className="h-px bg-[#999]/10">
                  <div className="h-full transition-all" style={{ width: `${p.pct}%`, backgroundColor: p.color }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardTitle className="mb-4">Top Source IPs</CardTitle>
          <CardContent className="flex flex-col gap-3">
            {TOP_IPS.map(ip => (
              <div key={ip.ip} className={`flex items-center justify-between p-3 rounded border ${ip.level === 'critical' ? 'border-[#fc4d4d]/30 bg-[#fc4d4d]/5' : ip.level === 'high' ? 'border-[#f6ad55]/30' : 'border-[#999]/10'}`}>
                <div>
                  <div className="font-mono text-xs text-white">{ip.ip}</div>
                  <div className="font-mono uppercase tracking-ui text-[9px] text-[#999] mt-0.5">{ip.country}</div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-xs text-white">{ip.count}</div>
                  {(ip.level === 'critical' || ip.level === 'high') && (
                    <Badge variant={ip.level === 'critical' ? 'red' : 'amber'} className="mt-1">{ip.level}</Badge>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card className="border-[#fc4d4d]/30">
        <CardTitle className="mb-4 text-[#fc4d4d]">⚠ DNS Tunneling Anomalies</CardTitle>
        <CardContent className="flex flex-col gap-3">
          {DNS_ANOMALIES.map((d, i) => (
            <div key={i} className="flex items-start justify-between border-b border-[#999]/10 pb-3 last:border-0 last:pb-0">
              <div>
                <div className="font-mono text-xs text-[#fc4d4d] break-all">{d.domain}</div>
                <div className="font-mono uppercase tracking-ui text-[9px] text-[#999] mt-1">{d.note}</div>
              </div>
              <Badge variant="red" className="ml-4 shrink-0">Entropy {d.entropy}</Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
