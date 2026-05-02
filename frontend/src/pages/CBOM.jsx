import { useEffect, useState } from 'react';
import { StatCard } from '../components/ui/StatCard';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Input, Textarea } from '../components/ui/Input';
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
const ASSET_TYPES = ['tls_certificate', 'signing_key', 'api_key', 'symmetric_key'];
const ENVIRONMENTS = ['production', 'staging', 'development'];
const ROTATION_POLICIES = ['none', 'manual', 'monthly', 'quarterly', 'semi-annual', 'annual'];
const SELECT_CLASSNAME = 'bg-black border border-[#999]/40 rounded px-3 py-2 text-white font-mono text-xs w-full focus:border-white focus:outline-none transition-colors';
const EMPTY_FORM = {
  asset_id: '',
  asset_type: 'tls_certificate',
  algorithm: '',
  system_name: '',
  environment: 'production',
  key_length: '',
  hash_algorithm: '',
  owner_team: '',
  issuer: '',
  expiry_date: '',
  last_rotated: '',
  rotation_policy: 'annual',
  notes: ''
};

export default function CBOM() {
  const [summary, setSummary] = useState({});
  const [assets, setAssets] = useState([]);
  const [roadmap, setRoadmap] = useState([]);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [formData, setFormData] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');
  const [formSuccess, setFormSuccess] = useState('');

  const loadMeta = async () => {
    const [summaryRes, roadmapRes] = await Promise.allSettled([
      api.cbomSummary(),
      api.cbomRoadmap()
    ]);

    if (summaryRes.status === 'fulfilled') {
      setSummary(summaryRes.value);
    }

    if (roadmapRes.status === 'fulfilled') {
      setRoadmap(roadmapRes.value?.roadmap || []);
    }
  };

  const loadAssets = async (riskFilter = filter) => {
    setLoading(true);
    try {
      const data = await api.cbom(riskFilter !== 'all' ? `?risk=${riskFilter}` : '');
      setAssets(Array.isArray(data) ? data : data?.assets || []);
    } catch {
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMeta();
  }, []);

  useEffect(() => {
    loadAssets(filter);
  }, [filter]);

  const updateForm = (field, value) => {
    setFormError('');
    setFormSuccess('');
    setFormData(current => ({ ...current, [field]: value }));
  };

  const toggleForm = () => {
    setFormError('');
    setFormSuccess('');
    setIsFormOpen(current => !current);
  };

  const resetForm = () => {
    setFormData(EMPTY_FORM);
    setFormError('');
    setFormSuccess('');
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setFormError('');
    setFormSuccess('');

    if (!formData.asset_id.trim() || !formData.asset_type.trim() || !formData.algorithm.trim() || !formData.system_name.trim()) {
      setFormError('Asset ID, asset type, algorithm, and system name are required.');
      return;
    }

    const parsedKeyLength = formData.key_length === '' ? null : Number(formData.key_length);
    if (parsedKeyLength !== null && (!Number.isInteger(parsedKeyLength) || parsedKeyLength < 1)) {
      setFormError('Key length must be a positive integer.');
      return;
    }

    const payload = {
      asset_id: formData.asset_id.trim(),
      asset_type: formData.asset_type.trim(),
      algorithm: formData.algorithm.trim(),
      system_name: formData.system_name.trim(),
      environment: formData.environment
    };

    if (parsedKeyLength !== null) payload.key_length = parsedKeyLength;
    if (formData.hash_algorithm.trim()) payload.hash_algorithm = formData.hash_algorithm.trim();
    if (formData.owner_team.trim()) payload.owner_team = formData.owner_team.trim();
    if (formData.issuer.trim()) payload.issuer = formData.issuer.trim();
    if (formData.expiry_date) payload.expiry_date = formData.expiry_date;
    if (formData.last_rotated) payload.last_rotated = formData.last_rotated;
    if (formData.rotation_policy) payload.rotation_policy = formData.rotation_policy;
    if (formData.notes.trim()) payload.notes = formData.notes.trim();

    setSubmitting(true);
    try {
      await api.createCbomAsset(payload);
      await Promise.all([loadMeta(), loadAssets(filter)]);
      setFormSuccess(`Asset ${payload.asset_id} saved.`);
      setIsFormOpen(false);
      setFormData(EMPTY_FORM);
    } catch (error) {
      setFormError(error.message || 'Failed to save asset.');
    } finally {
      setSubmitting(false);
    }
  };

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
                <div className="flex flex-col gap-4 mb-4">
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex gap-2 flex-wrap">
                      {FILTERS.map(f => (
                        <Button key={f} variant={filter === f ? 'primary' : 'secondary'} size="sm" onClick={() => setFilter(f)}>{f}</Button>
                      ))}
                    </div>
                    <Button variant={isFormOpen ? 'secondary' : 'primary'} size="sm" onClick={toggleForm}>
                      {isFormOpen ? 'Close Form' : 'Add Asset'}
                    </Button>
                  </div>

                  {formSuccess && (
                    <Card className="border-[#48bb78]/40">
                      <p className="font-mono uppercase tracking-ui text-[10px] text-[#48bb78]">{formSuccess}</p>
                    </Card>
                  )}

                  {isFormOpen && (
                    <Card>
                      <CardTitle className="mb-4">Add CBOM Asset</CardTitle>
                      <CardContent>
                        <form className="space-y-4" onSubmit={handleSubmit}>
                          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Asset ID</span>
                              <Input value={formData.asset_id} onChange={(e) => updateForm('asset_id', e.target.value)} placeholder="CBOM-013" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Asset Type</span>
                              <select
                                value={formData.asset_type}
                                onChange={(e) => updateForm('asset_type', e.target.value)}
                                className={SELECT_CLASSNAME}
                              >
                                {ASSET_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
                              </select>
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Algorithm</span>
                              <Input value={formData.algorithm} onChange={(e) => updateForm('algorithm', e.target.value)} placeholder="RSA, AES, CRYSTALS-Kyber" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">System Name</span>
                              <Input value={formData.system_name} onChange={(e) => updateForm('system_name', e.target.value)} placeholder="Customer Portal" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Environment</span>
                              <select
                                value={formData.environment}
                                onChange={(e) => updateForm('environment', e.target.value)}
                                className={SELECT_CLASSNAME}
                              >
                                {ENVIRONMENTS.map((environment) => <option key={environment} value={environment}>{environment}</option>)}
                              </select>
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Key Length</span>
                              <Input type="number" min="1" value={formData.key_length} onChange={(e) => updateForm('key_length', e.target.value)} placeholder="2048" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Hash Algorithm</span>
                              <Input value={formData.hash_algorithm} onChange={(e) => updateForm('hash_algorithm', e.target.value)} placeholder="SHA-256" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Owner Team</span>
                              <Input value={formData.owner_team} onChange={(e) => updateForm('owner_team', e.target.value)} placeholder="security" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Issuer</span>
                              <Input value={formData.issuer} onChange={(e) => updateForm('issuer', e.target.value)} placeholder="Internal CA" />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Expiry Date</span>
                              <Input type="date" value={formData.expiry_date} onChange={(e) => updateForm('expiry_date', e.target.value)} />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Last Rotated</span>
                              <Input type="date" value={formData.last_rotated} onChange={(e) => updateForm('last_rotated', e.target.value)} />
                            </label>
                            <label className="block">
                              <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Rotation Policy</span>
                              <select
                                value={formData.rotation_policy}
                                onChange={(e) => updateForm('rotation_policy', e.target.value)}
                                className={SELECT_CLASSNAME}
                              >
                                {ROTATION_POLICIES.map((policy) => <option key={policy} value={policy}>{policy}</option>)}
                              </select>
                            </label>
                          </div>

                          <label className="block">
                            <span className="font-mono uppercase tracking-ui text-[10px] text-[#999] mb-2 block">Notes</span>
                            <Textarea value={formData.notes} onChange={(e) => updateForm('notes', e.target.value)} rows={4} placeholder="Deployment context, migration blockers, ownership notes..." />
                          </label>

                          <p className="font-mono uppercase tracking-ui text-[10px] text-[#999]">
                            Risk, quantum posture, and expiry status are derived on save.
                          </p>

                          {formError && (
                            <div className="border border-[#fc4d4d]/40 rounded px-3 py-2">
                              <p className="font-mono uppercase tracking-ui text-[10px] text-[#fc4d4d]">{formError}</p>
                            </div>
                          )}

                          <div className="flex gap-3 flex-wrap">
                            <Button type="submit" variant="primary" size="sm" disabled={submitting}>
                              {submitting ? 'Saving...' : 'Save Asset'}
                            </Button>
                            <Button type="button" variant="secondary" size="sm" onClick={resetForm} disabled={submitting}>
                              Reset
                            </Button>
                          </div>
                        </form>
                      </CardContent>
                    </Card>
                  )}
                </div>
                <Card className="p-0">
                  <Table>
                    <Thead>
                      <tr>{['Asset ID', 'Type', 'Algorithm', 'System', 'Env', 'Expires', 'Quantum', 'Risk', 'Issues'].map(h => <Th key={h}>{h}</Th>)}</tr>
                    </Thead>
                    <tbody>
                      {loading ? (
                        <tr><Td colSpan={9} className="text-center text-[#999] py-8 font-mono text-[10px] uppercase tracking-ui">Loading...</Td></tr>
                      ) : assets.length === 0 ? (
                        <tr><Td colSpan={9} className="text-center text-[#999] py-8 font-mono text-[10px] uppercase tracking-ui">No assets</Td></tr>
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
