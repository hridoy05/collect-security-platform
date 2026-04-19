import { useEffect, useState } from 'react';
import { StatCard } from '../components/ui/StatCard';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Tabs } from '../components/ui/Tabs';
import { Table, Thead, Th, Tr, Td } from '../components/ui/Table';
import { api } from '../utils/api';

function riskVariant(r) {
  return r === 'red' ? 'red' : r === 'amber' ? 'amber' : r === 'green' ? 'green' : 'default';
}
function algVariant(alg = '') {
  const a = alg.toUpperCase();
  if (a.includes('MD5') || a.includes('SHA-1') || a.includes('3DES')) return 'red';
  if (a.includes('RSA') || a.includes('ECDSA') || a.includes('AES-128')) return 'amber';
  if (a.includes('AES-256') || a.includes('SHA-256') || a.includes('SHA-384')) return 'green';
  return 'default';
}

const TABS = [{ key: 'inventory', label: 'Inventory' }, { key: 'roadmap', label: 'Quantum Roadmap' }, { key: 'topics', label: 'Topics' }];
const FILTERS = ['all', 'red', 'amber', 'green'];

export default function CBOM() {
  const [summary, setSummary] = useState({});
  const [assets, setAssets] = useState([]);
  const [roadmap, setRoadmap] = useState([]);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.cbomSummary().then(setSummary).catch(() => {});
    api.cbomRoadmap().then(d => setRoadmap(d?.roadmap || [])).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    api.cbom(filter !== 'all' ? `?risk=${filter}` : '')
      .then(d => setAssets(Array.isArray(d) ? d : d?.assets || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [filter]);

  return (
    <div className="p-8 max-w-[1600px]">
      <div className="mb-8">
        <h1 className="font-mono uppercase tracking-ui text-2xl text-white">Crypto Asset Inventory</h1>
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">CBOM </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-4 mb-8">
        <StatCard label="Total Assets" value={summary.total} />
        <StatCard label="Red" value={summary.red} accent="red" />
        <StatCard label="Amber" value={summary.amber} accent="amber" />
        <StatCard label="Green" value={summary.green} accent="green" />
        <StatCard label="Quantum Vuln" value={summary.quantum_vulnerable} accent="amber" />
        <StatCard label="Expiring ≤30d" value={summary.expiring_soon} accent="amber" />
        <StatCard label="Expired" value={summary.expired} accent="red" />
      </div>

      <Tabs tabs={TABS}>
        {(active) => (
          <>
            {active === 'inventory' && (
              <div>
                <div className="flex gap-2 mb-4">
                  {FILTERS.map(f => (
                    <Button key={f} variant={filter === f ? 'primary' : 'secondary'} size="sm" onClick={() => setFilter(f)}>{f}</Button>
                  ))}
                </div>
                <Card className="p-0">
                  <Table>
                    <Thead>
                      <tr>{['Asset ID', 'Type', 'Algorithm', 'System', 'Env', 'Expires', 'Quantum', 'Risk', 'Issues'].map(h => <Th key={h}>{h}</Th>)}</tr>
                    </Thead>
                    <tbody>
                      {loading ? (
                        <tr><Td colSpan={9} className="text-center text-[#999] py-8 font-mono text-[10px] uppercase tracking-ui">Loading...</Td></tr>
                      ) : assets.map(a => {
                        const assetId = a.asset_id || a.assetId || a.id || '';
                        const days = a.days_to_expiry ?? a.daysToExpiry;
                        const qsafe = a.quantum_safe ?? a.quantumSafe;
                        const risk = a.risk_rating || a.riskRating;
                        return (
                          <Tr key={assetId}>
                            <Td className="font-mono text-[10px] text-[#999]">{String(assetId).slice(0, 14)}…</Td>
                            <Td><Badge>{a.asset_type || a.assetType}</Badge></Td>
                            <Td><Badge variant={algVariant(a.algorithm)}>{a.algorithm}</Badge></Td>
                            <Td className="text-xs">{a.system_name || a.systemName}</Td>
                            <Td><Badge>{a.environment}</Badge></Td>
                            <Td className={`font-mono text-xs ${days < 0 ? 'text-[#fc4d4d]' : days < 30 ? 'text-[#f6ad55]' : 'text-[#48bb78]'}`}>
                              {days != null ? `${days}d` : 'N/A'}
                            </Td>
                            <Td className={`font-mono text-xs ${qsafe ? 'text-[#48bb78]' : 'text-[#fc4d4d]'}`}>
                              {qsafe ? '✓ Safe' : '✗ Vuln'}
                            </Td>
                            <Td><Badge variant={riskVariant(risk)}>{risk?.toUpperCase()}</Badge></Td>
                            <Td className="text-xs text-[#999] max-w-[200px] truncate">{a.issues || '—'}</Td>
                          </Tr>
                        );
                      })}
                    </tbody>
                  </Table>
                </Card>
              </div>
            )}

            {active === 'roadmap' && (
              <Card className="p-0">
                <Table>
                  <Thead>
                    <tr>{['Asset ID', 'Current Alg', 'Recommended', 'Approach', 'Effort', 'Priority'].map(h => <Th key={h}>{h}</Th>)}</tr>
                  </Thead>
                  <tbody>
                    {roadmap.map((r, i) => {
                      const id = r.asset_id || r.assetId || '';
                      return (
                        <Tr key={i}>
                          <Td className="font-mono text-[10px] text-[#999]">{String(id).slice(0, 14)}…</Td>
                          <Td><Badge variant="amber">{r.current_algorithm || r.currentAlgorithm}</Badge></Td>
                          <Td className="text-xs">{r.recommended_algorithm || r.recommendedAlgorithm}</Td>
                          <Td className="text-xs text-[#999]">{r.migration_approach || r.migrationApproach}</Td>
                          <Td><Badge variant={r.effort === 'High' ? 'red' : r.effort === 'Medium' ? 'amber' : 'green'}>{r.effort}</Badge></Td>
                          <Td><Badge variant={r.priority === 'P1' ? 'red' : r.priority === 'P2' ? 'amber' : 'default'}>{r.priority}</Badge></Td>
                        </Tr>
                      );
                    })}
                  </tbody>
                </Table>
              </Card>
            )}

            {active === 'topics' && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { label: 'T1 — AES-256-GCM', body: 'Authenticated encryption with associated data. 256-bit key, random 96-bit IV per message, 128-bit authentication tag. Provides confidentiality and integrity in one operation.' },
                  { label: 'T2 — Quantum Vulnerability', body: "RSA and ECC are broken by Shor's algorithm on a sufficiently powerful quantum computer. CBOM flags these as quantum-vulnerable and recommends migration to Kyber (ML-KEM) or Dilithium (ML-DSA)." },
                  { label: 'T7 — CBOM & ICAM Cycle', body: 'Cryptographic Bill of Materials catalogs all cryptographic assets. The ICAM cycle covers Identify → Catalog → Assess → Migrate. Risk ratings (Red/Amber/Green) guide prioritized remediation.' },
                ].map(({ label, body }) => (
                  <Card key={label}>
                    <CardTitle className="mb-3">{label}</CardTitle>
                    <CardContent>
                      <p className="text-xs text-[#999] leading-relaxed">{body}</p>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </>
        )}
      </Tabs>
    </div>
  );
}
