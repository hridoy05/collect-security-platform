import { useEffect, useState } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { StatCard } from '../components/ui/StatCard';
import { Card, CardTitle, CardContent } from '../components/ui/Card';
import { api } from '../utils/api';

const MOCK_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  h: `${i}:00`,
  events: Math.floor(Math.random() * 400 + 100),
  alerts: Math.floor(Math.random() * 20 + 2),
}));

const MOCK_ATTACK = [
  { name: 'Brute Force', value: 35 },
  { name: 'DNS Tunnel', value: 18 },
  { name: 'Port Scan', value: 22 },
  { name: 'Exfil', value: 12 },
  { name: 'Other', value: 13 },
];
const ATTACK_COLORS = ['#fc4d4d', '#f6ad55', '#63b3ed', '#9f7aea', '#999'];

const MOCK_MITRE = [
  { tactic: 'Initial Access', count: 12 },
  { tactic: 'Execution', count: 8 },
  { tactic: 'Persistence', count: 6 },
  { tactic: 'Priv Esc', count: 4 },
  { tactic: 'Defense Evasion', count: 9 },
  { tactic: 'Exfiltration', count: 5 },
  { tactic: 'C2', count: 7 },
];

const TT = {
  contentStyle: { background: '#000', border: '1px solid #333', borderRadius: 6, fontFamily: 'monospace', fontSize: 11 },
  labelStyle: { color: '#999' },
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    api.dashboardStats().then(setStats).catch(() => {});
  }, []);

  const cbom = stats?.cbom ?? {};
  const alerts = stats?.alerts ?? {};
  const cve = stats?.cve ?? {};
  const ti = stats?.threatIntel ?? {};

  return (
    <div className="p-8 max-w-[1600px]">
      <div className="mb-8">
        <h1 className="font-mono uppercase tracking-ui text-2xl text-white">Security Dashboard</h1>
        <p className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">PayBD · Real-time Threat Visibility</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
        <StatCard label="Critical Alerts" value={alerts.critical_open} accent="red" />
        <StatCard label="Red CBOM Assets" value={cbom.red} accent="red" />
        <StatCard label="Quantum Vuln" value={cbom.quantum_vulnerable} accent="amber" />
        <StatCard label="KEV CVEs" value={cve.kev_open} accent="amber" />
        <StatCard label="Events 24h" value={alerts.last_24h} accent="blue" />
        <StatCard label="Active IOCs" value={ti.activeIOCs} accent="green" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <Card className="xl:col-span-2">
          <CardTitle className="mb-4">Security Events — Last 24 Hours</CardTitle>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={MOCK_TIMELINE}>
                <XAxis dataKey="h" tick={{ fill: '#999', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#999', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={35} />
                <Tooltip {...TT} />
                <Area type="monotone" dataKey="events" stroke="#63b3ed" fill="#63b3ed" fillOpacity={0.08} strokeWidth={1} name="Events" />
                <Area type="monotone" dataKey="alerts" stroke="#fc4d4d" fill="#fc4d4d" fillOpacity={0.08} strokeWidth={1} name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardTitle className="mb-4">Attack Distribution</CardTitle>
          <CardContent>
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={MOCK_ATTACK} dataKey="value" cx="50%" cy="50%" outerRadius={70} strokeWidth={0}>
                  {MOCK_ATTACK.map((_, i) => <Cell key={i} fill={ATTACK_COLORS[i]} />)}
                </Pie>
                <Tooltip {...TT} formatter={v => `${v}%`} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2">
              {MOCK_ATTACK.map((d, i) => (
                <span key={d.name} className="font-mono text-[10px] uppercase tracking-ui" style={{ color: ATTACK_COLORS[i] }}>
                  {d.name} {d.value}%
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card>
          <CardTitle className="mb-4">MITRE ATT&CK Coverage</CardTitle>
          <CardContent>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={MOCK_MITRE} layout="vertical" barSize={6}>
                <XAxis type="number" tick={{ fill: '#999', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis dataKey="tactic" type="category" tick={{ fill: '#999', fontSize: 9, fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={100} />
                <Tooltip {...TT} />
                <Bar dataKey="count" fill="#9f7aea" radius={0} name="Detections" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardTitle className="mb-4">Cryptographic Risk Summary</CardTitle>
          <CardContent className="flex flex-col gap-4 mt-2">
            {[
              { label: 'Red — Critical', val: cbom.red ?? 0, color: '#fc4d4d' },
              { label: 'Amber — High', val: cbom.amber ?? 0, color: '#f6ad55' },
              { label: 'Green — Safe', val: cbom.green ?? 0, color: '#48bb78' },
            ].map(({ label, val, color }) => {
              const total = (cbom.red ?? 0) + (cbom.amber ?? 0) + (cbom.green ?? 0);
              return (
                <div key={label}>
                  <div className="flex justify-between mb-1">
                    <span className="font-mono uppercase tracking-ui text-[10px] text-[#999]">{label}</span>
                    <span className="font-mono text-[10px]" style={{ color }}>{val}</span>
                  </div>
                  <div className="h-px bg-[#999]/10">
                    <div className="h-full transition-all" style={{ width: total ? `${(val / total) * 100}%` : '0%', backgroundColor: color }} />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
