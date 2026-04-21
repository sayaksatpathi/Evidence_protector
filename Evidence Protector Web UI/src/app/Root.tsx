import { Outlet } from './router';
import { NavBar } from './components/NavBar';

export function Root() {
  return (
    <div className="min-h-screen bg-background">
      <NavBar />
      <main className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
        <Outlet />
      </main>
    </div>
  );
}
