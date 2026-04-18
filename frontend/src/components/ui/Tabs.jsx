import { useState } from 'react';
import { cn } from '../../lib/utils';

export function Tabs({ tabs, children, className }) {
  const getKey = (t) => (typeof t === 'string' ? t : t.key);
  const getLabel = (t) => (typeof t === 'string' ? t : t.label);
  const [active, setActive] = useState(getKey(tabs[0]));

  return (
    <div className={cn(className)}>
      <div className="flex border-b border-[#999]/20 mb-6">
        {tabs.map((tab) => {
          const key = getKey(tab);
          const label = getLabel(tab);
          return (
            <button
              key={key}
              onClick={() => setActive(key)}
              className={cn(
                'font-mono uppercase tracking-ui text-[10px] px-4 py-2 border-b-2 -mb-px transition-colors duration-150',
                active === key
                  ? 'border-white text-white'
                  : 'border-transparent text-[#999] hover:text-white'
              )}
            >
              {label}
            </button>
          );
        })}
      </div>
      {typeof children === 'function' ? children(active) : children}
    </div>
  );
}
