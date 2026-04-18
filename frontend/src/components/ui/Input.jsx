import { cn } from '../../lib/utils';

export function Input({ className, ...props }) {
  return (
    <input
      className={cn(
        'bg-black border border-[#999]/40 rounded px-3 py-2 text-white font-mono text-xs w-full',
        'placeholder:text-[#999] focus:border-white focus:outline-none transition-colors',
        className
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }) {
  return (
    <textarea
      className={cn(
        'bg-black border border-[#999]/40 rounded px-3 py-2 text-white font-mono text-xs w-full resize-none',
        'placeholder:text-[#999] focus:border-white focus:outline-none transition-colors',
        className
      )}
      {...props}
    />
  );
}
