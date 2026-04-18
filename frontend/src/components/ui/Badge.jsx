import { cn } from '../../lib/utils';

const variants = {
  default: 'border-[#999] text-[#999]',
  red:    'border-[#fc4d4d] text-[#fc4d4d]',
  amber:  'border-[#f6ad55] text-[#f6ad55]',
  green:  'border-[#48bb78] text-[#48bb78]',
  blue:   'border-[#63b3ed] text-[#63b3ed]',
  purple: 'border-[#9f7aea] text-[#9f7aea]',
};

export function Badge({ variant = 'default', className, children, ...props }) {
  return (
    <span
      className={cn(
        'inline-block font-mono uppercase tracking-ui text-[10px] border rounded px-1.5 py-0.5',
        variants[variant] ?? variants.default,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
