import { Link } from '../router';
import { FileQuestion, Home } from 'lucide-react';

export function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
      <div className="flex items-center justify-center w-24 h-24 rounded-full bg-secondary mb-6">
        <FileQuestion className="w-12 h-12 text-muted-foreground" />
      </div>
      <h1 className="text-4xl font-semibold text-foreground mb-3">404 - Page Not Found</h1>
      <p className="text-muted-foreground mb-8 text-center max-w-md">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <Link
        to="/"
        className="flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-primary-foreground rounded transition-colors"
      >
        <Home className="w-4 h-4" />
        Back to Dashboard
      </Link>
    </div>
  );
}
