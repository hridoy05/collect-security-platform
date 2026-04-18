import { useEffect, useState } from 'react';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Tabs } from '../components/ui/Tabs';
import { Table, Thead, Th, Tr, Td } from '../components/ui/Table';
import { api } from '../utils/api';

export default function ThreatIntel() {
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
