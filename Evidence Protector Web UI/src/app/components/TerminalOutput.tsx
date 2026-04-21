import { useEffect, useRef } from 'react';

interface TerminalOutputProps {
  output: string[];
  isRunning?: boolean;
}

const MAX_RENDER_LINES = 1000;

export function TerminalOutput({ output, isRunning = false }: TerminalOutputProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const totalLines = output.length;
  const isTruncated = totalLines > MAX_RENDER_LINES;
  const startIndex = isTruncated ? totalLines - MAX_RENDER_LINES : 0;
  const visibleLines = isTruncated ? output.slice(startIndex) : output;

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [output]);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between gap-3 px-4 py-2 bg-background border-b border-border">
        <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${isRunning ? 'bg-primary animate-pulse' : 'bg-muted-foreground'}`} />
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Console</span>
        </div>
        <span className="text-[11px] text-muted-foreground font-mono">{totalLines.toLocaleString()} lines</span>
      </div>
      <div
        ref={scrollRef}
        className="flex-1 bg-background p-4 overflow-auto font-mono text-sm text-foreground leading-relaxed scrollbar-thin scrollbar-track-transparent"
        style={{ fontFamily: 'var(--font-mono)' }}
      >
        {visibleLines.length === 0 ? (
          <div className="text-muted-foreground">Waiting for output...</div>
        ) : (
          <>
            {isTruncated && (
              <div className="text-muted-foreground mb-2">
                Showing last {visibleLines.length.toLocaleString()} of {totalLines.toLocaleString()} lines.
              </div>
            )}
            {visibleLines.map((line, index) => {
              const lineNumber = startIndex + index + 1;
              return (
                <div key={lineNumber} className="flex items-start gap-4">
                  <span className="text-muted-foreground select-none shrink-0 w-12 text-right tabular-nums">
                    {String(lineNumber).padStart(3, '0')}
                  </span>
                  <span className="whitespace-pre">
                    {line}
                  </span>
                </div>
              );
            })}
          </>
        )}
        {isRunning && (
          <div className="flex items-center gap-2 text-primary mt-2">
            <div className="w-1 h-4 bg-primary animate-pulse" />
            <span className="text-xs font-semibold uppercase tracking-wider">Processing…</span>
          </div>
        )}
      </div>
    </div>
  );
}
