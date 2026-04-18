import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

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

export default function Network() {
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
