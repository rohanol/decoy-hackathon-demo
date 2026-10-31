import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';

/** Console routes need a signed-in analyst; everyone else sees the landing page. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { ready, user } = useAuth();
  const location = useLocation();
  if (!ready) return null;
  if (!user) return <Navigate to="/welcome" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}
