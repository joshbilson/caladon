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
import { getStoreProxy, deriveStoreKeyHex } from '~/lib/store';
import { warmupEmbedder, hydrateRagIndex, resetRagIndex } from '~/lib/rag/retrieval';
import useConversationList from '~/store/useConversationList';
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

/** Seeds the sidebar conversation cache from the on-device store. It MUST render INSIDE
 *  <AuthContext.Provider> because it calls useAuthContext (via useConversationList) — so it lives
 *  here as a child, NOT in the provider body, which executes above its own context value (calling
 *  it there throws "useAuthContext should be used inside AuthProvider"). */
const StoreSeeder = (): null => {
  useConversationList();
  return null;
};

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

  // (Sidebar cache seeding from the on-device store is done by <StoreSeeder/> rendered INSIDE the
  // provider return below — it CANNOT run here in the provider body, which executes above its own
  // context value. It self-gates on an unlocked session + open store and re-runs when auth flips.)

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
      const account = result.identity.accountId;
      setAccountId(account);

      // Open the on-device encrypted SQLite store with `device_store_key(root)` BEFORE we flip
      // `isAuthenticated` (applyUserContext). The seeding hooks (useConversationList here,
      // useHydrateConversation on the chat route) self-gate on `store.isOpen` and re-run when
      // `isAuthenticated` changes — so the store must be open by the time auth flips for the first
      // seed to land. `deriveStoreKeyHex(root)` reuses the wasm the handshake just initialised
      // (the arg is ignored when already loaded); the raw key bytes are zeroed inside kdf.ts and
      // the key never leaves the worker after INIT. We swallow store-open errors (e.g. OPFS
      // unavailable falls back to an in-memory store inside the worker) so a store failure can
      // never block establishing the attested chat session.
      try {
        await getStoreProxy().openStore(await deriveStoreKeyHex(result.identity.root));
      } catch (storeErr) {
        console.error('[caladon] device store open failed (history/RAG disabled this session):', storeErr);
      }

      // The seed-derived identity IS the single local user. LibreChat gates the USER-role query
      // — and therefore conversation initialization in ChatRoute (`roles?.USER != null`) — on
      // `user?.role` being set, so we synthesize a local USER. Without a role the app authenticates
      // but never creates a conversation, leaving the chat pane blank.
      const caladonUser = {
        id: account,
        username: account.slice(0, 12),
        name: 'Caladon',
        email: '',
        avatar: '',
        role: SystemRoles.USER,
        provider: 'caladon',
      } as unknown as t.TUser;
      applyUserContext({ isAuthenticated: true, user: caladonUser, redirect: '/c/new', token: undefined });

      // RAG init — strictly non-blocking and OFF the unlock path's critical line. Warm the MiniLM
      // embedder (so the first ingest/query isn't paying cold-start) and rebuild the in-memory
      // cosine index from the persisted, encrypted vectors. Both are fire-and-forget: failures are
      // swallowed inside the helpers and must never affect auth. (The sidebar/list seed is driven
      // declaratively by `useConversationList()` mounted in this provider, which fires once auth
      // flips and the store is open.)
      void warmupEmbedder();
      void hydrateRagIndex(true).catch(() => undefined);
    },
    [applyUserContext],
  );

  const lock = useCallback(() => {
    caladonLock();
    setAccountId(undefined);
    // Wipe the on-device store (logout / panic) and drop the in-memory RAG index. clearStore keeps
    // the store open but empties every table; resetRagIndex drops the cosine matrix. Fire-and-forget
    // so a store error can't wedge the lock/navigation.
    void getStoreProxy()
      .clearStore()
      .catch((err) => console.error('[caladon] device store clear on lock failed:', err));
    resetRagIndex();
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
      // Same teardown as lock(): empty the encrypted store and drop the RAG index. Fire-and-forget.
      void getStoreProxy()
        .clearStore()
        .catch((err) => console.error('[caladon] device store clear on logout failed:', err));
      resetRagIndex();
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

  return (
    <AuthContext.Provider value={memoedValue}>
      <StoreSeeder />
      {children}
    </AuthContext.Provider>
  );
};

const useAuthContext = () => {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error('useAuthContext should be used inside AuthProvider');
  }

  return context;
};

export { AuthContextProvider, useAuthContext, AuthContext };
