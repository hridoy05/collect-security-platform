import { useEffect, useState } from 'react';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Input, Textarea } from '../components/ui/Input';
import { api } from '../utils/api';

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

export default function MLDetection() {
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
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">Z-Score · Isolation Forest · UEBA ·</p>
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
