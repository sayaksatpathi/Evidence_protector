import { useState } from 'react';
import { Link } from '../router';
import { ArrowLeft, ArrowRight, BookOpen, CheckCircle2, Shield, GitCompareArrows, FolderOpenDot, Camera } from 'lucide-react';
import { getGuideDismissed, setGuideDismissed } from '../lib/organizer';

const steps = [
  {
    title: 'Start on the Dashboard',
    icon: Shield,
    body: 'Use the dashboard to confirm API settings, browse recent activity, and jump into the core flows.',
  },
  {
    title: 'Run Scan, Sign, and Verify',
    icon: CheckCircle2,
    body: 'Upload a log file to scan gaps, sign it to create a manifest, and verify it later against that manifest.',
  },
  {
    title: 'Use Ghost Protocol',
    icon: BookOpen,
    body: 'Build a baseline, analyze a file, collect receipts, and correlate them for additional forensic evidence.',
  },
  {
    title: 'Organize baselines',
    icon: FolderOpenDot,
    body: 'Group baseline records into named collections so you can keep per-environment evidence sets separate.',
  },
  {
    title: 'Compare reports',
    icon: GitCompareArrows,
    body: 'Compare two results side by side to understand how integrity, signals, or manifests changed.',
  },
  {
    title: 'Capture release evidence',
    icon: Camera,
    body: 'Export a proof pack and capture screenshots of key screens before publishing a release.',
  },
];

export function Guide() {
  const [step, setStep] = useState(0);
  const [dismissed, setDismissedState] = useState(getGuideDismissed());

  const active = steps[step];
  const ActiveIcon = active.icon;

  const finish = () => {
    setGuideDismissed(true);
    setDismissedState(true);
  };

  if (dismissed) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-secondary rounded transition-colors">
            <ArrowLeft className="w-5 h-5 text-muted-foreground" />
          </Link>
          <div>
            <h1 className="text-2xl font-semibold text-foreground">Onboarding Walkthrough</h1>
            <p className="text-muted-foreground">The guide is hidden for now. You can reopen it from this page.</p>
          </div>
        </div>
        <button
          onClick={() => {
            setGuideDismissed(false);
            setDismissedState(false);
            setStep(0);
          }}
          className="px-4 py-2 rounded-md bg-primary text-primary-foreground"
        >
          Show walkthrough again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-secondary rounded transition-colors">
          <ArrowLeft className="w-5 h-5 text-muted-foreground" />
        </Link>
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Onboarding Walkthrough</h1>
          <p className="text-muted-foreground">A short guided tour through the release-ready workflows.</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-6">
        <div className="flex items-center justify-between gap-4">
          <div className="text-sm text-muted-foreground font-mono">Step {step + 1} of {steps.length}</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider">Evidence Protector</div>
        </div>

        <div className="h-2 rounded-full bg-secondary overflow-hidden">
          <div className="h-full bg-primary" style={{ width: `${((step + 1) / steps.length) * 100}%` }} />
        </div>

        <div className="flex items-start gap-4">
          <div className="p-3 rounded-lg bg-primary/10 text-primary border border-primary/20">
            <ActiveIcon className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h2 className="text-xl font-semibold text-foreground">{active.title}</h2>
            <p className="text-muted-foreground leading-relaxed">{active.body}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <Link to="/scan" className="px-4 py-3 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors">Open Scan</Link>
          <Link to="/baselines" className="px-4 py-3 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors">Open Baselines</Link>
          <Link to="/compare" className="px-4 py-3 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors">Open Compare</Link>
          <Link to="/release-evidence" className="px-4 py-3 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors">Open Evidence Pack</Link>
        </div>

        <div className="flex flex-col sm:flex-row gap-2 sm:justify-between pt-2">
          <button
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 disabled:opacity-50 transition-colors inline-flex items-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
          <div className="flex gap-2">
            <button
              onClick={finish}
              className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors"
            >
              Dismiss
            </button>
            <button
              onClick={() => {
                if (step === steps.length - 1) {
                  finish();
                  return;
                }
                setStep((s) => Math.min(steps.length - 1, s + 1));
              }}
              className="px-4 py-2 rounded-md bg-primary text-primary-foreground inline-flex items-center gap-2"
            >
              {step === steps.length - 1 ? 'Finish' : 'Next'}
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
