// @vitest-environment jsdom
import { AuthenticationError, type PublicUser, type SessionInfo } from '@acme/auth-core';
import { act, cleanup, render, renderHook, screen } from '@testing-library/react';
import { createElement, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { evaluateGuard, type AuthClient, type AuthState } from '../src/index.js';
import { AuthGuard, AuthProvider, useAuth, useAuthClient, useAuthState, useCan, useGuard, useLogin } from '../src/react/index.js';
import { rbac } from './harness.js';

afterEach(cleanup);

const user: PublicUser = { id: 'u1', identifier: 'ada@example.com', roles: ['editor'] };
const session: SessionInfo = {
  id: 's1',
  createdAt: 900,
  lastUsedAt: 900,
  expiresAt: 99_999,
  authenticatedAt: 900,
  methods: ['pwd'],
  assurance: 'aal1',
  deviceBound: true,
};
const authenticated: AuthState = { status: 'authenticated', user, session };

/** A client whose state the test controls, so the hooks can be tested without a server. */
function fakeClient(initial: AuthState) {
  let state = initial;
  const listeners = new Set<(state: AuthState) => void>();
  const set = (next: AuthState) => {
    state = next;
    for (const listener of listeners) listener(state);
    return state;
  };
  const client = {
    getState: () => state,
    subscribe: (listener: (state: AuthState) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    check: (requirement = {}) => evaluateGuard(state, requirement, { rbac, nowSec: 1000 }),
    can: (action: string) => state.status === 'authenticated' && rbac.grants(state.user.roles, action as never),
    loginWithPassword: vi.fn(async () => set(authenticated)),
    loginWithPasskey: vi.fn(async () => set(authenticated)),
    submitMfa: vi.fn(async () => set(authenticated)),
    cancelMfa: vi.fn(() => void set({ status: 'unauthenticated' })),
    logout: vi.fn(async () => void set({ status: 'unauthenticated' })),
  } as unknown as AuthClient;
  return { client, set, listeners };
}

function wrapperFor(client: AuthClient) {
  return ({ children }: { children: ReactNode }) => createElement(AuthProvider, { client }, children);
}

describe('AuthProvider', () => {
  it('adds no markup of its own', () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const { container } = render(createElement(AuthProvider, { client }, createElement('p', null, 'content')));
    expect(container.innerHTML).toBe('<p>content</p>');
  });

  it('makes the client available, and the hooks fail clearly without it', () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const { result } = renderHook(() => useAuthClient(), { wrapper: wrapperFor(client) });
    expect(result.current).toBe(client);

    const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => renderHook(() => useAuthClient())).toThrow(/inside an <AuthProvider>/);
    quiet.mockRestore();
  });
});

describe('useAuthState and useAuth', () => {
  it('re-renders when the state changes and stops listening on unmount', () => {
    const { client, set, listeners } = fakeClient({ status: 'loading' });
    const { result, unmount } = renderHook(() => useAuthState(), { wrapper: wrapperFor(client) });
    expect(result.current).toEqual({ status: 'loading' });

    act(() => void set(authenticated));
    expect(result.current).toBe(authenticated);

    act(() => void set({ status: 'unauthenticated' }));
    expect(result.current).toEqual({ status: 'unauthenticated' });

    unmount();
    expect(listeners.size).toBe(0);
  });

  it('derives the common values', () => {
    const { client, set } = fakeClient({ status: 'loading' });
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    expect(result.current).toMatchObject({ isLoading: true, isAuthenticated: false, user: null, session: null });

    act(() => void set(authenticated));
    expect(result.current).toMatchObject({ isLoading: false, isAuthenticated: true, user, session });
    expect(result.current.client).toBe(client);
  });

  it('logs out through the client', async () => {
    const { client } = fakeClient(authenticated);
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await act(async () => {
      await result.current.logout();
    });
    expect(result.current.isAuthenticated).toBe(false);
  });
});

describe('useLogin', () => {
  it('tracks a successful sign-in', async () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const { result } = renderHook(() => useLogin(), { wrapper: wrapperFor(client) });
    expect(result.current).toMatchObject({ pending: false, error: null });

    let returned: AuthState | undefined;
    await act(async () => {
      returned = await result.current.loginWithPassword({ identifier: 'ada@example.com', password: 'pw' });
    });
    expect(returned).toBe(authenticated);
    expect(result.current).toMatchObject({ pending: false, error: null, state: authenticated });
    expect(client.loginWithPassword).toHaveBeenCalledWith({ identifier: 'ada@example.com', password: 'pw' });
  });

  it('is pending while the request is in flight', async () => {
    const { client, set } = fakeClient({ status: 'unauthenticated' });
    let finish: () => void = () => undefined;
    (client.loginWithPassword as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise<AuthState>((resolve) => (finish = () => resolve(set(authenticated)))),
    );
    const { result } = renderHook(() => useLogin(), { wrapper: wrapperFor(client) });

    let call: Promise<unknown> = Promise.resolve();
    act(() => {
      call = result.current.loginWithPassword({ identifier: 'ada@example.com', password: 'pw' });
    });
    expect(result.current.pending).toBe(true);

    await act(async () => {
      finish();
      await call;
    });
    expect(result.current.pending).toBe(false);
  });

  it('reports a failure through `error` instead of throwing, and can be reset', async () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const failure = new AuthenticationError('INVALID_CREDENTIALS');
    (client.loginWithPassword as ReturnType<typeof vi.fn>).mockRejectedValue(failure);
    const { result } = renderHook(() => useLogin(), { wrapper: wrapperFor(client) });

    let returned: AuthState | undefined = authenticated;
    await act(async () => {
      returned = await result.current.loginWithPassword({ identifier: 'ada@example.com', password: 'nope' });
    });
    expect(returned).toBeUndefined();
    expect(result.current.error).toBe(failure);
    expect(result.current.error?.message).toBe('The credentials are not valid.');
    expect(result.current.pending).toBe(false);

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();
  });

  it('clears the previous error when a new attempt starts', async () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const login = client.loginWithPassword as ReturnType<typeof vi.fn>;
    login.mockRejectedValueOnce(new AuthenticationError('INVALID_CREDENTIALS'));
    const { result } = renderHook(() => useLogin(), { wrapper: wrapperFor(client) });
    await act(async () => {
      await result.current.loginWithPassword({ identifier: 'a', password: 'b' });
    });
    expect(result.current.error).not.toBeNull();
    await act(async () => {
      await result.current.loginWithPassword({ identifier: 'a', password: 'c' });
    });
    expect(result.current.error).toBeNull();
  });

  it('covers the second factor and passkeys', async () => {
    const { client, set } = fakeClient({ status: 'unauthenticated' });
    const { result } = renderHook(() => useLogin(), { wrapper: wrapperFor(client) });

    act(() => void set({ status: 'mfa_required', methods: ['totp'], reason: 'enrolled', expiresAt: 2000 }));
    expect(result.current.state.status).toBe('mfa_required');
    await act(async () => {
      await result.current.submitMfa({ method: 'totp', code: '123456' });
    });
    expect(client.submitMfa).toHaveBeenCalledWith({ method: 'totp', code: '123456' });
    expect(result.current.state.status).toBe('authenticated');

    act(() => result.current.cancelMfa());
    expect(client.cancelMfa).toHaveBeenCalled();
    await act(async () => {
      await result.current.loginWithPasskey({ identifier: 'ada@example.com' });
    });
    expect(client.loginWithPasskey).toHaveBeenCalledWith({ identifier: 'ada@example.com' });
  });
});

describe('useGuard and useCan', () => {
  it('re-evaluate when the state changes', () => {
    const { client, set } = fakeClient({ status: 'loading' });
    const { result } = renderHook(() => ({ guard: useGuard({ permissions: ['invoice:write'] }), can: useCan('invoice:write') }), {
      wrapper: wrapperFor(client),
    });
    expect(result.current).toEqual({ guard: { status: 'pending' }, can: false });

    act(() => void set({ status: 'unauthenticated' }));
    expect(result.current.guard).toMatchObject({ status: 'deny', action: 'login' });

    act(() => void set(authenticated));
    expect(result.current).toEqual({ guard: { status: 'allow' }, can: true });

    act(() => void set({ status: 'authenticated', user: { ...user, roles: ['viewer'] }, session }));
    expect(result.current.guard).toMatchObject({ status: 'deny', action: 'forbidden' });
    expect(result.current.can).toBe(false);
  });
});

describe('AuthGuard', () => {
  const tree = (client: AuthClient, props: Parameters<typeof AuthGuard>[0]) =>
    createElement(AuthProvider, { client }, createElement(AuthGuard, props, createElement('section', null, 'secret area')));

  it('renders the pending content, then the fallback, then the children as the state changes', () => {
    const { client, set } = fakeClient({ status: 'loading' });
    const fallback = vi.fn((result: { action: string; reason: string }) => createElement('a', { href: `/${result.action}` }, result.reason));
    render(tree(client, { fallback, pending: createElement('span', null, 'one moment') }));
    expect(screen.getByText('one moment')).toBeTruthy();
    expect(screen.queryByText('secret area')).toBeNull();

    act(() => void set({ status: 'unauthenticated' }));
    expect(screen.getByText('not signed in').getAttribute('href')).toBe('/login');
    expect(fallback).toHaveBeenLastCalledWith({ status: 'deny', action: 'login', reason: 'not signed in' });
    expect(screen.queryByText('secret area')).toBeNull();

    act(() => void set(authenticated));
    expect(screen.getByText('secret area')).toBeTruthy();
    expect(screen.queryByText('not signed in')).toBeNull();
  });

  it('hides the children when the requirement is not met and tells the fallback why', () => {
    const { client } = fakeClient(authenticated);
    const fallback = vi.fn(() => createElement('p', null, 'step up first'));
    render(tree(client, { require: { assurance: 'aal2' }, fallback }));
    expect(screen.getByText('step up first')).toBeTruthy();
    expect(screen.queryByText('secret area')).toBeNull();
    expect(fallback).toHaveBeenCalledWith({ status: 'deny', action: 'step_up', reason: 'requires a second factor' });
  });

  it('accepts a plain node as fallback and renders nothing by default', () => {
    const { client } = fakeClient({ status: 'unauthenticated' });
    const { container, rerender } = render(tree(client, { fallback: createElement('p', null, 'please sign in') }));
    expect(container.innerHTML).toBe('<p>please sign in</p>');

    rerender(tree(client, {}));
    expect(container.innerHTML).toBe('');
  });

  it('renders the children with no wrapper element', () => {
    const { client } = fakeClient(authenticated);
    const { container } = render(tree(client, {}));
    expect(container.innerHTML).toBe('<section>secret area</section>');
  });
});
