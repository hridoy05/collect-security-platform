import { cn } from '../../lib/utils';

export function Table({ className, children }) {
  return (
    <div className="overflow-x-auto">
      <table className={cn('w-full border-collapse text-sm', className)}>{children}</table>
    </div>
  );
}

export function Thead({ children }) {
  return <thead>{children}</thead>;
}

export function Th({ className, children }) {
  return (
    <th className={cn('font-mono uppercase tracking-ui text-[10px] text-[#999] text-left py-2 px-3 border-b border-[#999]/20', className)}>
      {children}
    </th>
  );
}

export function Tr({ className, children }) {
  return (
    <tr className={cn('border-b border-[#999]/10 hover:bg-white/5 transition-colors', className)}>
      {children}
    </tr>
  );
}

export function Td({ className, children, colSpan }) {
  return (
    <td colSpan={colSpan} className={cn('py-2.5 px-3 text-sm text-white', className)}>
      {children}
    </td>
  );
}
