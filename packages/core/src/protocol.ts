/**
 * Request and response bodies of the HTTP endpoints. The server handler and the browser client
 * both compile against these definitions.
 *
 * WebAuthn payloads are typed as plain JSON objects here, because this package has no
 * dependencies. The server and client narrow them with the SimpleWebAuthn types.
 */
import type { ErrorBody } from './errors.js';
import type { AccountSecurity, MfaMethod, PasskeyInfo, PublicUser, SessionInfo } from './types.js';

export interface ErrorResponse {
  error: ErrorBody;
}

/** An access token with the user and session it belongs to. Times are epoch seconds. */
export interface AccessGrantResponse {
  status: 'authenticated';
  accessToken: string;
  accessTokenExpiresAt: number;
  user: PublicUser;
  session: SessionInfo;
}

export interface MfaRequiredResponse {
  status: 'mfa_required';
  ticket: string;
  methods: MfaMethod[];
  reason: 'enrolled' | 'risk';
  expiresAt: number;
}

export type LoginResponse = AccessGrantResponse | MfaRequiredResponse;

export interface PasswordLoginRequest {
  identifier: string;
  password: string;
}

export interface PasskeyLoginOptionsRequest {
  identifier?: string;
}

/** `options` is the JSON form of the WebAuthn options, to pass to the browser ceremony. */
export interface PasskeyOptionsResponse {
  challengeId: string;
  options: Record<string, unknown>;
}

/** `response` is the JSON form of the credential returned by the browser ceremony. */
export interface PasskeyLoginRequest {
  challengeId: string;
  response: Record<string, unknown>;
}

export interface MfaVerifyRequest {
  ticket: string;
  method: MfaMethod;
  code: string;
}

export type ReauthenticateRequest =
  | { method: 'password'; password: string }
  | { method: MfaMethod; code: string }
  | { method: 'passkey'; challengeId: string; response: Record<string, unknown> };

export interface SessionResponse {
  user: PublicUser;
  session: SessionInfo;
  security: AccountSecurity;
}

export interface SessionListResponse {
  sessions: SessionInfo[];
}

export interface TotpEnrollmentResponse {
  enrollmentId: string;
  /** Base32 secret, for manual entry. */
  secret: string;
  /** `otpauth://` URI, to render as a QR code. */
  otpauthUri: string;
}

export interface TotpConfirmRequest {
  enrollmentId: string;
  code: string;
}

export interface RecoveryCodesResponse {
  recoveryCodes: string[];
}

export interface PasskeyRegisterRequest {
  challengeId: string;
  response: Record<string, unknown>;
  name?: string;
}

export interface PasskeyListResponse {
  passkeys: PasskeyInfo[];
}

export interface PasswordChangeRequest {
  currentPassword: string;
  newPassword: string;
}
