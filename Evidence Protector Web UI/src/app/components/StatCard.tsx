import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
  trend?: {
    value: string;
    positive: boolean;
  };
}

export function StatCard({ icon: Icon, label, value, trend }: StatCardProps) {
  return (
    <div className="bg-card border border-border rounded-lg p-5 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="p-2 bg-primary/10 border border-primary/20 rounded-md">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        {trend && (
          <span className={`text-xs font-semibold tracking-wider ${trend.positive ? 'text-success' : 'text-destructive'}`}>
            {trend.value}
          </span>
        )}
      </div>
      <div className="space-y-1">
        <div className="text-3xl font-semibold text-foreground leading-none">{value}</div>
        <div className="text-xs text-muted-foreground uppercase tracking-wider">{label}</div>
      </div>
    </div>
  );
}
