import {
  useMemo,
  useState,
  useEffect,
  useContext,
  useCallback,
  createContext,
} from 'react';
import { useRecoilState, useSetRecoilState } from 'recoil';
import { useNavigate } from 'react-router-dom';
import { SystemRoles, isSystemRoleName } from 'librechat-data-provider';
import type * as t from 'librechat-data-provider';
import type { ReactNode } from 'react';
import { useGetRole } from '~/data-provider';
import { TAuthConfig, TUserContext, TAuthContext } from '~/common';
import {
  caladonUnlock,
  caladonLock,
  caladonIdentity,
  isUnlocked as caladonIsUnlocked,
  signRequest as caladonSignRequest,
} from '~/lib/caladon';
import store from '~/store';

/**
 * Caladon AuthContext (SURGERY.md §A3 / §D). LibreChat's Passport/JWT/refresh identity is
 * amputated: there is no password, no email, no server-side user record, no bearer token. Identity
 * is a key derived from a local SEED. Unlocking the seed runs the full fail-closed handshake
 * (onboard → attest → verify → session) in the `caladon-core` WASM via the @caladon/protocol SDK;
 * the seed and all keys never leave the device. Every gateway request is signed per-request
 * (`Authorization: Swifty …`) — useSSE + request interceptors read `caladon.signRequest`.
 *
 * The legacy `token`/`login`/`logout` surface is preserved (60+ call sites depend on the shape)
 * but re-pointed: `token` is undefined (no JWT), `isAuthenticated` reflects the unlock state.
 */

const AuthContext = (import.meta.hot?.data?.__AuthContext ??
  createContext<TAuthContext | undefined>(undefined)) as React.Context<TAuthContext | undefined>;
if (import.meta.hot) {
  import.meta.hot.data.__AuthContext = AuthContext;
}

const AuthContextProvider = ({
  authConfig,
  children,
}: {
  authConfig?: TAuthConfig;
  children: ReactNode;
}) => {
  const [user, setUser] = useRecoilState(store.user);
  const [error, setError] = useState<string | undefined>(undefined);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(caladonIsUnlocked());
  const [accountId, setAccountId] = useState<string | undefined>(
    caladonIdentity()?.accountId,
  );
  const setQueriesEnabled = useSetRecoilState<boolean>(store.queriesEnabled);

  const userRoleName = user?.role ?? '';
  const isCustomRole = isAuthenticated && !!user?.role && !isSystemRoleName(user.role);

  const { data: userRole = null } = useGetRole(SystemRoles.USER, {
    enabled: !!(isAuthenticated && (user?.role ?? '')),
  });
  const { data: adminRole = null } = useGetRole(SystemRoles.ADMIN, {
    enabled: !!(isAuthenticated && user?.role === SystemRoles.ADMIN),
  });
  const { data: customRole = null } = useGetRole(isCustomRole ? userRoleName : '_', {
    enabled: isCustomRole,
  });

  const navigate = useNavigate();

  const applyUserContext = useCallback(
    (userContext: TUserContext) => {
      const { isAuthenticated: authed, user: nextUser, redirect } = userContext;
      setUser(nextUser);
      setIsAuthenticated(authed);
      if (authed) {
        setQueriesEnabled(true);
      }
      if (redirect != null) {
        navigate(redirect, { replace: true });
      }
    },
    [navigate, setUser, setQueriesEnabled],
  );

  /** Unlock the seed → fail-closed handshake → establish the attested session. */
  const unlock = useCallback(
    async (seed: Uint8Array) => {
      setError(undefined);
      const result = await caladonUnlock(seed);
      setAccountId(result.identity.accountId);
      applyUserContext({ isAuthenticated: true, user, redirect: '/c/new', token: undefined });
    },
    [applyUserContext, user],
  );

  const lock = useCallback(() => {
    caladonLock();
    setAccountId(undefined);
    applyUserContext({ isAuthenticated: false, user: undefined, redirect: '/login', token: undefined });
  }, [applyUserContext]);

  /** Legacy login(): no password auth. A seed-unlock screen drives `unlock` directly. */
  const login = useCallback((_data: t.TLoginUser) => {
    setError('Caladon uses a local seed, not a password. Unlock your seed to continue.');
  }, []);

  const logout = useCallback(
    (redirect?: string) => {
      caladonLock();
      setAccountId(undefined);
      applyUserContext({
        isAuthenticated: false,
        user: undefined,
        redirect: redirect ?? '/login',
        token: undefined,
      });
    },
    [applyUserContext],
  );

  useEffect(() => {
    if (authConfig?.test === true) {
      return;
    }
    // No silent JWT refresh — identity is the in-memory seed. If the seed is not unlocked,
    // the router gates to the seed-unlock screen.
    if (!caladonIsUnlocked()) {
      setIsAuthenticated(false);
    }
  }, [authConfig?.test]);

  const caladon = useMemo(
    () => ({
      accountId,
      isUnlocked: isAuthenticated,
      unlock,
      lock,
      signRequest: caladonSignRequest,
    }),
    [accountId, isAuthenticated, unlock, lock],
  );

  const memoedValue = useMemo(
    () => ({
      user,
      token: undefined,
      error,
      login,
      logout,
      setError,
      caladon,
      roles: {
        [SystemRoles.USER]: userRole,
        [SystemRoles.ADMIN]: adminRole,
        ...(isCustomRole && customRole ? { [userRoleName]: customRole } : {}),
      },
      isAuthenticated,
    }),
    [
      user,
      error,
      isAuthenticated,
      caladon,
      login,
      logout,
      userRole,
      adminRole,
      isCustomRole,
      userRoleName,
      customRole,
    ],
  );

  return <AuthContext.Provider value={memoedValue}>{children}</AuthContext.Provider>;
};

const useAuthContext = () => {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error('useAuthContext should be used inside AuthProvider');
  }

  return context;
};

export { AuthContextProvider, useAuthContext, AuthContext };
