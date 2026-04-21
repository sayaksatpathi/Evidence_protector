import { CheckCircle2, AlertTriangle, XCircle, Loader2, AlertCircle, PenLine, Fingerprint, FileText } from 'lucide-react';

type Status =
  | 'CLEAN'
  | 'SIGNED'
  | 'TAMPERED'
  | 'GAPS_FOUND'
  | 'NO_TIMESTAMPS'
  | 'GHOST_CLEAN'
  | 'GHOST_SIGNALS'
  | 'GHOST_BASELINE'
  | 'GHOST_RECEIPTS'
  | 'RUNNING'
  | 'ERROR';

interface StatusBadgeProps {
  status: Status;
  className?: string;
}

const statusConfig = {
  CLEAN: {
    icon: CheckCircle2,
    label: 'CLEAN',
    className: 'bg-success/10 text-success border-success/30',
  },
  SIGNED: {
    icon: PenLine,
    label: 'SIGNED',
    className: 'bg-success/10 text-success border-success/30',
  },
  TAMPERED: {
    icon: XCircle,
    label: 'TAMPERED',
    className: 'bg-destructive/10 text-destructive border-destructive/30',
  },
  GAPS_FOUND: {
    icon: AlertTriangle,
    label: 'GAPS DETECTED',
    className: 'bg-warning/10 text-warning border-warning/30',
  },
  NO_TIMESTAMPS: {
    icon: AlertCircle,
    label: 'NO TIMESTAMPS',
    className: 'bg-warning/10 text-warning border-warning/30',
  },
  GHOST_CLEAN: {
    icon: CheckCircle2,
    label: 'GHOST CLEAN',
    className: 'bg-success/10 text-success border-success/30',
  },
  GHOST_SIGNALS: {
    icon: AlertTriangle,
    label: 'GHOST SIGNALS',
    className: 'bg-warning/10 text-warning border-warning/30',
  },
  GHOST_BASELINE: {
    icon: Fingerprint,
    label: 'GHOST BASELINE',
    className: 'bg-primary/10 text-primary border-primary/30',
  },
  GHOST_RECEIPTS: {
    icon: FileText,
    label: 'GHOST RECEIPTS',
    className: 'bg-primary/10 text-primary border-primary/30',
  },
  RUNNING: {
    icon: Loader2,
    label: 'RUNNING',
    className: 'bg-primary/10 text-primary border-primary/30',
  },
  ERROR: {
    icon: AlertCircle,
    label: 'ERROR',
    className: 'bg-destructive/10 text-destructive border-destructive/30',
  },
};

export function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <div
      className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-md border ${config.className} ${className}`}
    >
      <Icon className={`w-3.5 h-3.5 ${status === 'RUNNING' ? 'animate-spin' : ''}`} />
      <span className="text-[11px] font-semibold tracking-wider">{config.label}</span>
    </div>
  );
}
