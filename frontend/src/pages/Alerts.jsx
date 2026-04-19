import { useEffect, useState } from 'react';
import { StatCard } from '../components/ui/StatCard';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Tabs } from '../components/ui/Tabs';
import { api } from '../utils/api';
import { formatDistanceToNow } from 'date-fns';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_TABS = [
  { key: 'all', label: 'All' },
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

function sevVariant(s) { return s === 'critical' ? 'red' : s === 'high' ? 'amber' : s === 'medium' ? 'blue' : 'default'; }
function stVariant(s) { return s === 'open' ? 'red' : s === 'investigating' ? 'amber' : 'green'; }

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [counts, setCounts] = useState({});
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);

  const load = async (sev) => {
    setLoading(true);
    try {
      const data = await api.alerts(sev !== 'all' ? `?severity=${sev}` : '');
      const arr = (Array.isArray(data) ? data : data?.alerts || [])
        .sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));
      setAlerts(arr);
      if (sev === 'all') {
        const c = arr.reduce((acc, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc; }, {});
        setCounts({ ...c, open: arr.filter(a => a.status === 'open').length, resolved: arr.filter(a => a.status === 'resolved').length, total: arr.length });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(filter); }, [filter]);

  const updateStatus = async (id, status) => {
    await api.updateAlert(id, status);
    setAlerts(a => a.map(x => (x.alert_id === id || x.id === id) ? { ...x, status } : x));
  };

  const correlate = async () => {
    setCorrelating(true);
    try {
      const res = await api.correlate();
      alert(`Correlated ${res.correlated} new alert(s)`);
      load(filter);
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="font-mono uppercase tracking-ui text-2xl text-white">SIEM Alerts</h1>
          <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">Real-time Correlation</p>
        </div>
        <Button variant="secondary" onClick={correlate} disabled={correlating}>
          {correlating ? 'Running...' : 'Run Correlation'}
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Critical" value={counts.critical} accent="red" />
        <StatCard label="Total" value={counts.total} />
        <StatCard label="Open" value={counts.open} accent="amber" />
        <StatCard label="Resolved" value={counts.resolved} accent="green" />
      </div>

      <Tabs tabs={SEV_TABS}>
        {(active) => {
          if (active !== filter) setFilter(active);
          return loading ? (
            <div className="text-center font-mono uppercase tracking-ui text-[10px] text-[#999] py-16">Loading...</div>
          ) : alerts.length === 0 ? (
            <div className="text-center font-mono uppercase tracking-ui text-[10px] text-[#999] py-16">No alerts</div>
          ) : (
            <div className="flex flex-col gap-3">
              {alerts.map(a => (
                <Card key={a.id || a.alert_id} className="flex flex-col gap-2">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant={sevVariant(a.severity)}>{a.severity}</Badge>
                      <Badge variant={stVariant(a.status)}>{a.status}</Badge>
                      {a.mitre_technique && <Badge variant="blue">{a.mitre_technique}</Badge>}
                    </div>
                    <span className="font-mono text-[10px] text-[#999] shrink-0">
                      {a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : ''}
                    </span>
                  </div>
                  <div className="text-sm text-white">{a.title}</div>
                  {a.description && <div className="text-xs text-[#999]">{a.description}</div>}
                  <div className="flex items-center gap-4 flex-wrap mt-1">
                    {a.source_ip && <span className="font-mono text-[10px] text-[#999]">SRC {a.source_ip}</span>}
                    {a.affected_user && <span className="font-mono text-[10px] text-[#999]">USER {a.affected_user}</span>}
                    {a.alert_score && <span className="font-mono text-[10px] text-[#999]">SCORE {Number(a.alert_score).toFixed(1)}</span>}
                  </div>
                  {a.status !== 'resolved' && (
                    <div className="flex gap-2 mt-1">
                      {a.status === 'open' && (
                        <Button variant="secondary" size="sm" onClick={() => updateStatus(a.alert_id || a.id, 'investigating')}>Investigate</Button>
                      )}
                      <Button variant="secondary" size="sm" onClick={() => updateStatus(a.alert_id || a.id, 'resolved')}>Resolve</Button>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          );
        }}
      </Tabs>
    </div>
  );
}
