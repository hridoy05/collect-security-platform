import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { Input } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { api } from '../utils/api';

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@connect.com');
  const [password, setPassword] = useState('Admin@123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await api.login(email, password);
      localStorage.setItem('connect_token', data.token);
      localStorage.setItem('connect_user', JSON.stringify(data.user));
      navigate('/');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center">
      <div className="w-80">
        <div className="text-center mb-10">
          <Shield size={32} className="mx-auto mb-4 text-white" strokeWidth={1} />
          <div className="font-mono uppercase tracking-ui text-base text-white">Connect</div>
          <div className="font-mono uppercase tracking-ui text-[10px] text-[#999] mt-1">Security Analytics Platform</div>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-4">
          <div>
            <label className="block font-mono uppercase tracking-ui text-[10px] text-[#999] mb-1.5">Email</label>
            <Input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@connect.com" required />
          </div>
          <div>
            <label className="block font-mono uppercase tracking-ui text-[10px] text-[#999] mb-1.5">Password</label>
            <Input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" required />
          </div>
          {error && (
            <div className="border border-[#fc4d4d]/40 rounded p-2 text-[#fc4d4d] font-mono text-[10px]">{error}</div>
          )}
          <Button type="submit" variant="primary" className="w-full mt-2" disabled={loading}>
            {loading ? 'Authenticating...' : 'Sign In'}
          </Button>
        </form>

        <div className="mt-6 text-center text-[#999] font-mono text-[10px] uppercase tracking-ui">
          Demo: admin@connect.com / Admin@123
        </div>
      </div>
    </div>
  );
}
