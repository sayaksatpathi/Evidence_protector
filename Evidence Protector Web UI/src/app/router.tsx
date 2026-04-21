import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  ReactNode,
} from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface RouterContextValue {
  path: string;
  params: Record<string, string>;
  navigate: (to: string) => void;
}

interface RouteConfig {
  path: string;
  Component: React.ComponentType;
}

// ─── Context ──────────────────────────────────────────────────────────────────

const RouterContext = createContext<RouterContextValue>({
  path: '/',
  params: {},
  navigate: () => {},
});

const OutletContext = createContext<ReactNode>(null);

// ─── Path matching ────────────────────────────────────────────────────────────

function matchPath(
  pattern: string,
  path: string
): Record<string, string> | null {
  if (pattern === '*') return {};

  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = path.split('/').filter(Boolean);

  if (patternParts.length !== pathParts.length) return null;

  const params: Record<string, string> = {};
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(':')) {
      params[patternParts[i].slice(1)] = pathParts[i];
    } else if (patternParts[i] !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

// ─── RouterProvider ───────────────────────────────────────────────────────────

interface RouterProviderProps {
  routes: RouteConfig[];
  layout?: React.ComponentType;
}

export function RouterProvider({ routes, layout: Layout }: RouterProviderProps) {
  const [path, setPath] = useState('/');

  const navigate = useCallback((to: string) => {
    setPath(to);
  }, []);

  // Find matching route
  let matchedComponent: ReactNode = null;
  let matchedParams: Record<string, string> = {};

  for (const route of routes) {
    const params = matchPath(route.path, path);
    if (params !== null) {
      matchedParams = params;
      matchedComponent = <route.Component />;
      break;
    }
  }

  // Fallback to wildcard
  if (!matchedComponent) {
    const wildcard = routes.find((r) => r.path === '*');
    if (wildcard) matchedComponent = <wildcard.Component />;
  }

  const contextValue: RouterContextValue = { path, params: matchedParams, navigate };

  if (Layout) {
    return (
      <RouterContext.Provider value={contextValue}>
        <OutletContext.Provider value={matchedComponent}>
          <Layout />
        </OutletContext.Provider>
      </RouterContext.Provider>
    );
  }

  return (
    <RouterContext.Provider value={contextValue}>
      {matchedComponent}
    </RouterContext.Provider>
  );
}

// ─── Hooks ────────────────────────────────────────────────────────────────────

export function useNavigate() {
  return useContext(RouterContext).navigate;
}

export function useLocation() {
  const { path } = useContext(RouterContext);
  return { pathname: path };
}

export function useParams() {
  return useContext(RouterContext).params;
}

// ─── Components ───────────────────────────────────────────────────────────────

interface LinkProps
  extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string;
  children: ReactNode;
  className?: string;
}

export function Link({ to, children, className, ...rest }: LinkProps) {
  const { navigate } = useContext(RouterContext);
  return (
    <a
      href="#"
      className={className}
      onClick={(e) => {
        e.preventDefault();
        navigate(to);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}

export function Outlet() {
  const outlet = useContext(OutletContext);
  return <>{outlet}</>;
}
