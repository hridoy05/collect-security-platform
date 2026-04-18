import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { Shield, BarChart2, AlertTriangle, Globe, Brain, Network, Wifi, WifiOff, LogOut, X } from 'lucide-react';
import { cn } from '../lib/utils';

const NAV = [
  { to: '/',             icon: BarChart2,     label: 'Dashboard'    },
  { to: '/cbom',         icon: Shield,        label: 'Crypto Assets'},
  { to: '/alerts',       icon: AlertTriangle, label: 'SIEM Alerts'  },
  { to: '/threat-intel', icon: Globe,         label: 'Threat Intel' },
  { to: '/ml',           icon: Brain,         label: 'ML Detection' },
  { to: '/network',      icon: Network,       label: 'Network'      },
];

export default function Layout() {
  const navigate = useNavigate();
  const [connected, setConnected] = useState(false);
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    const socket = io(import.meta.env.VITE_WS_URL || 'http://localhost:4000');
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('alert:new', (alert) => {
      if (alert.severity === 'critical' || alert.severity === 'high') {
        const id = Date.now();
        setToasts(t => [...t, { id, alert }]);
        setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 6000);
      }
    });
    return () => socket.disconnect();
  }, []);

  const logout = () => {
    localStorage.removeItem('connect_token');
    localStorage.removeItem('connect_user');
    navigate('/login');
  };

  return (
    <div className="flex h-full bg-black text-white">
      {/* Sidebar */}
      <aside className="w-[220px] shrink-0 border-r border-[#999]/20 flex flex-col">
        <div className="px-6 py-5 border-b border-[#999]/20">
          <div className="font-mono uppercase tracking-ui text-white text-sm leading-none">Connect</div>
          <div className="font-mono uppercase tracking-ui text-[#999] text-[10px] mt-1">Security Analytics</div>
        </div>

        <nav className="flex-1 py-4 overflow-y-auto">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-6 py-2.5 font-mono uppercase tracking-ui text-[10px] transition-colors duration-150',
                  isActive
                    ? 'text-white border-l-2 border-white pl-[22px]'
                    : 'text-[#999] hover:text-white'
                )
              }
            >
              <Icon size={13} strokeWidth={1.5} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-6 py-4 border-t border-[#999]/20 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            {connected
              ? <Wifi size={12} className="text-[#48bb78]" />
              : <WifiOff size={12} className="text-[#fc4d4d]" />}
            <span className="font-mono uppercase tracking-ui text-[9px] text-[#999]">
              {connected ? 'Live' : 'Offline'}
            </span>
          </div>
          <button onClick={logout} className="text-[#999] hover:text-white transition-colors">
            <LogOut size={13} strokeWidth={1.5} />
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 min-w-0 overflow-y-auto">
        <Outlet />
      </main>

      {/* Toast notifications */}
      <div className="fixed top-4 right-4 flex flex-col gap-2 z-50 w-72">
        {toasts.map(({ id, alert }) => (
          <div key={id} className="bg-black border border-[#fc4d4d]/50 rounded p-3 flex items-start gap-3">
            <AlertTriangle size={13} className="text-[#fc4d4d] mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="font-mono uppercase tracking-ui text-[10px] text-[#fc4d4d]">{alert.severity}</div>
              <div className="text-xs text-white mt-0.5 truncate">{alert.title}</div>
            </div>
            <button onClick={() => setToasts(t => t.filter(x => x.id !== id))} className="text-[#999] hover:text-white">
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
