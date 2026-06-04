import { createBrowserRouter, Navigate, Outlet, useParams } from 'react-router-dom';
import {
  VerifyEmail,
  Registration,
  ResetPassword,
  ApiErrorWatcher,
  TwoFactorScreen,
  RequestPasswordReset,
} from '~/components/Auth';
import useHydrateConversation from '~/store/useHydrateConversation';
import CaladonUnlock from '~/components/Auth/CaladonUnlock';
import { MarketplaceProvider } from '~/components/Agents/MarketplaceContext';
import AgentMarketplace from '~/components/Agents/Marketplace';
import { OAuthSuccess, OAuthError } from '~/components/OAuth';
import { AuthContextProvider } from '~/hooks/AuthContext';
import WithRum from '~/lib/rum/WithRum';
import RouteErrorBoundary from './RouteErrorBoundary';
import StartupLayout from './Layouts/Startup';
import LoginLayout from './Layouts/Login';
import dashboardRoutes from './Dashboard';
import ShareRoute from './ShareRoute';
import ChatRoute from './ChatRoute';
import Search from './Search';
import Root from './Root';

/**
 * Caladon route override (SURGERY.md §A3, gap G2). Upstream renders `<Login/>` (password/OAuth) at
 * `/login`. Caladon has no password — identity is a local 32-byte seed — so the `login` path renders
 * `<CaladonUnlock/>` (Create new identity / Restore from recovery code → `caladon.unlock(seed)` →
 * fail-closed handshake) instead. Everything else (layouts, guards, chat routes) is upstream.
 *
 * The unlocked-guard needs no new code: identity is in-memory only, so `isAuthenticated` starts
 * false on every load; `routes/ChatRoute` calls `useAuthRedirect()` which navigates locked users to
 * `/login`, and `routes/Root` renders nothing until unlocked. AuthContext.lock/logout also navigate
 * to `/login`. So a locked user always lands here, and this screen is the only way out.
 */

const AuthLayout = () => (
  <AuthContextProvider>
    <WithRum>
      <Outlet />
    </WithRum>
    <ApiErrorWatcher />
  </AuthContextProvider>
);

/**
 * Caladon device-store hydration wrapper for the chat route. On a deep-link / hard reload to
 * `/c/<id>`, the gateway has NO server-side message store, so the chat view restores its history
 * from the on-device encrypted store. `useHydrateConversation` reads the `:conversationId` route
 * param and — gated on an unlocked session + an open store, and only when the messages cache for
 * that id is still empty — seeds it from `StoreProxy.hydrate(id)` (live state always wins). It
 * renders `<ChatRoute/>` unchanged; the wrapper only adds the side effect.
 */
const StoreHydrationWrapper = () => {
  const { conversationId } = useParams();
  useHydrateConversation(conversationId);
  return <ChatRoute />;
};

const loadInlinePromptsView = () =>
  import('~/components/Prompts/layouts/InlinePromptsView').then((m) => ({
    Component: m.default,
  }));

const loadSkillsView = () =>
  import('~/components/Skills/layouts/SkillsView').then((m) => ({
    Component: m.default,
  }));

const baseEl = document.querySelector('base');
const baseHref = baseEl?.getAttribute('href') || '/';

export const router = createBrowserRouter(
  [
    {
      path: 'share/:shareId',
      element: <ShareRoute />,
      errorElement: <RouteErrorBoundary />,
    },
    {
      path: 'oauth',
      errorElement: <RouteErrorBoundary />,
      children: [
        {
          path: 'success',
          element: <OAuthSuccess />,
        },
        {
          path: 'error',
          element: <OAuthError />,
        },
      ],
    },
    {
      path: '/',
      element: <StartupLayout />,
      errorElement: <RouteErrorBoundary />,
      children: [
        {
          path: 'register',
          element: <Registration />,
        },
        {
          path: 'forgot-password',
          element: <RequestPasswordReset />,
        },
        {
          path: 'reset-password',
          element: <ResetPassword />,
        },
      ],
    },
    {
      path: 'verify',
      element: <VerifyEmail />,
      errorElement: <RouteErrorBoundary />,
    },
    {
      element: <AuthLayout />,
      errorElement: <RouteErrorBoundary />,
      children: [
        {
          path: '/',
          element: <LoginLayout />,
          children: [
            {
              path: 'login',
              element: <CaladonUnlock />,
            },
            {
              path: 'login/2fa',
              element: <TwoFactorScreen />,
            },
          ],
        },
        dashboardRoutes,
        {
          path: '/',
          element: <Root />,
          children: [
            {
              index: true,
              element: <Navigate to="/c/new" replace={true} />,
            },
            {
              path: 'c/:conversationId?',
              element: <StoreHydrationWrapper />,
            },
            {
              path: 'search',
              element: <Search />,
            },
            {
              path: 'prompts',
              element: <Navigate to="/prompts/new" replace={true} />,
            },
            {
              path: 'prompts/new',
              lazy: loadInlinePromptsView,
            },
            {
              path: 'prompts/:promptId',
              lazy: loadInlinePromptsView,
            },
            {
              path: 'skills',
              lazy: loadSkillsView,
            },
            {
              path: 'skills/new',
              lazy: loadSkillsView,
            },
            {
              path: 'skills/:skillId',
              lazy: loadSkillsView,
            },
            {
              path: 'skills/:skillId/edit',
              lazy: loadSkillsView,
            },
            {
              path: 'agents',
              element: (
                <MarketplaceProvider>
                  <AgentMarketplace />
                </MarketplaceProvider>
              ),
            },
            {
              path: 'agents/:category',
              element: (
                <MarketplaceProvider>
                  <AgentMarketplace />
                </MarketplaceProvider>
              ),
            },
          ],
        },
      ],
    },
  ],
  { basename: baseHref },
);
