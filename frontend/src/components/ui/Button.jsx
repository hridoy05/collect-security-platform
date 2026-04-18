import { cn } from '../../lib/utils';

export function Button({ variant = 'primary', size = 'md', className, children, ...props }) {
  return (
    <button
      className={cn(
        'font-mono uppercase tracking-ui font-normal transition-all duration-200 cursor-pointer disabled:opacity-50',
        variant === 'primary' && 'bg-transparent border border-white text-white rounded-full px-6 py-3 text-xs hover:bg-white hover:text-black',
        variant === 'secondary' && 'bg-transparent border border-[#999] text-white rounded px-3 py-1.5 text-xs hover:border-white',
        variant === 'ghost' && 'bg-transparent text-white text-xs hover:opacity-75',
        size === 'sm' && 'text-[10px] px-3 py-1',
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
