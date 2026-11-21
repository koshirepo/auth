import type { ResolvedConfig } from '../config.js';

type CookieConfig = ResolvedConfig['sessions']['cookie'];

function attributes(config: CookieConfig, maxAgeSec: number): string {
  const parts = [
    `Path=${config.path}`,
    `Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`,
    // These two are not configurable: the refresh token must never be readable by script or sent in clear text.
    'HttpOnly',
    'Secure',
    `SameSite=${config.sameSite === 'lax' ? 'Lax' : 'Strict'}`,
  ];
  if (config.domain !== undefined) parts.push(`Domain=${config.domain}`);
  return parts.join('; ');
}

/** The `Set-Cookie` value that stores a refresh token. */
export function refreshCookie(config: CookieConfig, refreshToken: string, maxAgeSec: number): string {
  return `${config.name}=${refreshToken}; ${attributes(config, maxAgeSec)}`;
}

/** The `Set-Cookie` value that removes the refresh token. */
export function clearedRefreshCookie(config: CookieConfig): string {
  return `${config.name}=; ${attributes(config, 0)}`;
}

/** Reads one cookie from a `Cookie` request header. */
export function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator === -1) continue;
    if (pair.slice(0, separator).trim() === name) {
      const value = pair.slice(separator + 1).trim();
      return value.length > 0 ? value : undefined;
    }
  }
  return undefined;
}
