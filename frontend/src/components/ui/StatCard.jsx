import { cn } from '../../lib/utils';
import { Card, CardTitle } from './Card';

const accentMap = {
  white: 'text-white',
  red:   'text-[#fc4d4d]',
  amber: 'text-[#f6ad55]',
  green: 'text-[#48bb78]',
  blue:  'text-[#63b3ed]',
};

export function StatCard({ label, value, sub, accent = 'white', className }) {
  return (
    <Card className={cn('flex flex-col gap-2', className)}>
      <CardTitle>{label}</CardTitle>
      <div className={cn('text-3xl font-mono font-normal', accentMap[accent] ?? 'text-white')}>
        {value ?? '—'}
      </div>
      {sub && <div className="text-[#999] text-[10px] font-mono uppercase tracking-ui">{sub}</div>}
    </Card>
  );
}
