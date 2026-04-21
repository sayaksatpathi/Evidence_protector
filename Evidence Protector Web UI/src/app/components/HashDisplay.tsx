import { Copy, Check } from 'lucide-react';
import { useState } from 'react';
import { Button } from './ui/button';

interface HashDisplayProps {
  hash: string;
  label?: string;
}

export function HashDisplay({ hash, label = 'Root Hash' }: HashDisplayProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const truncatedHash = hash.length > 16 ? `${hash.slice(0, 8)}...${hash.slice(-8)}` : hash;

  return (
    <div className="flex items-center gap-3 bg-card border border-border rounded p-4">
      <div className="flex-1">
        <div className="text-xs text-muted-foreground mb-1">{label}</div>
        <div className="font-mono text-sm text-foreground" title={hash}>
          {truncatedHash}
        </div>
      </div>
      <Button
        onClick={handleCopy}
        variant="ghost"
        size="icon"
        aria-label="Copy hash"
        title="Copy hash"
      >
        {copied ? <Check className="text-success" /> : <Copy className="text-muted-foreground" />}
      </Button>
    </div>
  );
}
