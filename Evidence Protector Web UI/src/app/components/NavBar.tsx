import { Link, useLocation } from '../router';
import { Shield, LayoutDashboard, ScanLine, PenLine, FileCheck, History, BookOpenText, Layers3, GitCompareArrows, ClipboardList, ShieldCheck } from 'lucide-react';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/scan', label: 'Scan', icon: ScanLine },
  { path: '/sign', label: 'Sign', icon: PenLine },
  { path: '/verify', label: 'Verify', icon: FileCheck },
  { path: '/history', label: 'History', icon: History },
  { path: '/baselines', label: 'Baselines', icon: Layers3 },
  { path: '/compare', label: 'Compare', icon: GitCompareArrows },
  { path: '/audit', label: 'Audit', icon: ShieldCheck },
  { path: '/guide', label: 'Guide', icon: BookOpenText },
  { path: '/release-evidence', label: 'Evidence', icon: ClipboardList },
];

export function NavBar() {
  const location = useLocation();

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-card/80 backdrop-blur supports-[backdrop-filter]:bg-card/70">
      <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-8 flex-wrap">
            <Link to="/" className="flex items-center gap-2 text-foreground hover:opacity-90 transition-opacity">
            <Shield className="w-6 h-6 text-primary" />
            <span className="font-semibold text-lg tracking-wide">Evidence Protector</span>
          </Link>
          <div className="flex items-center gap-1 flex-wrap">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`
                    flex items-center gap-2 px-3 py-2 rounded-md transition-colors border
                    ${isActive
                      ? 'bg-primary/10 text-primary border-primary/30'
                      : 'text-muted-foreground hover:text-foreground hover:bg-secondary/70 border-transparent hover:border-border'
                    }
                  `}
                >
                  <Icon className="w-4 h-4" />
                  <span className="text-xs font-semibold uppercase tracking-wider">{item.label}</span>
                </Link>
              );
            })}
          </div>
        </div>
          <div className="px-3 py-1 bg-secondary/60 border border-border rounded text-[11px] text-muted-foreground font-mono tracking-wider">
            v2.4.1
          </div>
        </div>
      </div>
    </nav>
  );
}
