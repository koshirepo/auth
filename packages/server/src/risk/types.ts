import type { RiskDecision } from '@acme/auth-core';
import type { DeviceRecord, User } from '../adapters/types.js';

export interface GeoLocation {
  /** ISO 3166-1 alpha-2 country code. */
  country?: string;
  latitude?: number;
  longitude?: number;
}

/** Resolves an IP address to a location. The library does not bundle a GeoIP database. */
export type GeoLocator = (ip: string) => GeoLocation | null | undefined | Promise<GeoLocation | null | undefined>;

/** Everything a risk signal can look at. */
export interface RiskInput {
  user: User;
  ip: string | undefined;
  userAgent: string | undefined;
  /** Thumbprint of the DPoP key that signed the login request, when device binding is in use. */
  deviceKey: string | undefined;
  /** The location of `ip`, when a locator is configured and knows it. */
  location: GeoLocation | null;
  now: Date;
  /** Devices this user has signed in from before. Empty on the account's first login. */
  devices: readonly DeviceRecord[];
  /** Recent failed sign-in attempts for this account and from this IP. */
  failures: { account: number; ip: number };
}

export interface RiskSignalResult {
  name: string;
  score: number;
}

/**
 * A risk signal returns a score when it fires and null when it does not.
 *
 * A signal may carry a `locate` function. The engine calls the first one it finds, once per
 * assessment, and passes the result to every signal as `input.location`.
 */
export interface RiskSignal {
  (input: RiskInput): RiskSignalResult | null | Promise<RiskSignalResult | null>;
  locate?: GeoLocator;
}

export interface RiskAssessment {
  /** Sum of the signal scores, capped at 100. */
  score: number;
  decision: RiskDecision;
  signals: RiskSignalResult[];
  location: GeoLocation | null;
}
