import { AccountError, PasskeyError, RequestError, type PasskeyInfo } from '@acme/auth-core';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { AuthAdapter, PasskeyCredential } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import { toPasskeyInfo } from '../sessions/views.js';
import type { Clock } from '../util/clock.js';
import { randomId, randomToken } from '../util/crypto.js';
import { fromBase64Url, toBase64Url, utf8Encode } from '../util/encoding.js';

export interface PasskeyRegistrationOptions {
  challengeId: string;
  /** Pass to `startRegistration({ optionsJSON })` from `@simplewebauthn/browser`. */
  options: PublicKeyCredentialCreationOptionsJSON;
}

export interface PasskeyLoginOptions {
  challengeId: string;
  /** Pass to `startAuthentication({ optionsJSON })` from `@simplewebauthn/browser`. */
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface VerifiedPasskey {
  userId: string;
  passkeyId: string;
  /** True when the authenticator checked a PIN or biometric. */
  userVerified: boolean;
}

export interface PasskeyServiceOptions {
  config: NonNullable<ResolvedConfig['passkeys']>;
  adapter: AuthAdapter;
  clock: Clock;
  audit: AuditEmitter;
}

const MAX_NAME_LENGTH = 100;
const MAX_ID_LENGTH = 1024;

/**
 * WebAuthn registration and authentication. Option generation and response verification are done
 * by `@simplewebauthn/server`. This class adds challenge storage, credential storage and the
 * single-use rules around them.
 */
export class PasskeyService {
  constructor(private readonly options: PasskeyServiceOptions) {}

  async registrationOptions(userId: string): Promise<PasskeyRegistrationOptions> {
    const { config, adapter } = this.options;
    const user = await adapter.users.findById(userId);
    if (!user) throw new AccountError('USER_NOT_FOUND');
    const existing = await adapter.credentials.listPasskeys(userId);

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpId,
      userName: user.identifier,
      userID: utf8Encode(user.id) as Uint8Array<ArrayBuffer>,
      attestationType: 'none',
      // Stops the same authenticator from being registered twice for one account.
      excludeCredentials: existing.map((passkey) => ({ id: passkey.credentialId, transports: passkey.transports })),
      authenticatorSelection: { residentKey: config.residentKey, userVerification: config.userVerification },
    });

    const challengeId = randomToken(16);
    await adapter.ephemeral.set(
      `webauthn:register:${challengeId}`,
      { userId, challenge: options.challenge },
      config.challengeTtlSec,
    );
    return { challengeId, options };
  }

  async register(
    userId: string,
    input: { challengeId: string; response: RegistrationResponseJSON; name?: string },
    ctx: RequestContext = {},
  ): Promise<PasskeyInfo> {
    const { config, adapter, clock, audit } = this.options;
    const challenge = await this.takeChallenge('register', input.challengeId);
    if (challenge.userId !== userId) throw new PasskeyError('PASSKEY_CHALLENGE_INVALID');
    if (input.name !== undefined && (typeof input.name !== 'string' || input.name.length > MAX_NAME_LENGTH)) {
      throw new RequestError('REQUEST_INVALID', { details: { field: 'name' } });
    }

    let info: NonNullable<Awaited<ReturnType<typeof verifyRegistrationResponse>>['registrationInfo']>;
    try {
      const verification = await verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: config.origins,
        expectedRPID: config.rpId,
        requireUserVerification: config.userVerification === 'required',
      });
      if (!verification.verified || !verification.registrationInfo) throw new Error('The registration was not verified.');
      info = verification.registrationInfo;
    } catch (cause) {
      throw new PasskeyError('PASSKEY_VERIFICATION_FAILED', { cause });
    }

    const passkey: PasskeyCredential = {
      id: randomId(),
      userId,
      credentialId: info.credential.id,
      publicKey: toBase64Url(info.credential.publicKey),
      counter: info.credential.counter,
      transports: [...(info.credential.transports ?? [])],
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      name: input.name?.trim() || null,
      createdAt: clock.now(),
      lastUsedAt: null,
    };
    if (!(await adapter.credentials.savePasskey(passkey))) {
      // The credential id is already registered, to this account or another one.
      throw new PasskeyError('PASSKEY_VERIFICATION_FAILED', { debug: 'The credential id is already registered.' });
    }
    await audit.emit(
      'passkey.registered',
      { outcome: 'success', userId, data: { passkeyId: passkey.id, deviceType: passkey.deviceType, backedUp: passkey.backedUp } },
      ctx,
    );
    return toPasskeyInfo(passkey);
  }

  async list(userId: string): Promise<PasskeyInfo[]> {
    return (await this.options.adapter.credentials.listPasskeys(userId)).map(toPasskeyInfo);
  }

  /** Removes a passkey. Refuses to remove the only way a user has left to sign in. */
  async remove(userId: string, passkeyId: string, ctx: RequestContext = {}): Promise<void> {
    const { adapter, audit } = this.options;
    const passkeys = await adapter.credentials.listPasskeys(userId);
    if (!passkeys.some((passkey) => passkey.id === passkeyId)) throw new PasskeyError('PASSKEY_NOT_FOUND');
    if (passkeys.length === 1 && (await adapter.credentials.getPasswordHash(userId)) === null) {
      throw new RequestError('REQUEST_INVALID', { details: { reason: 'last_credential' } });
    }
    if (!(await adapter.credentials.deletePasskey(userId, passkeyId))) throw new PasskeyError('PASSKEY_NOT_FOUND');
    await audit.emit('passkey.removed', { outcome: 'success', userId, data: { passkeyId } }, ctx);
  }

  /**
   * Options for signing in. With a user id, the options list that user's credentials, which is
   * only done when `identifierHints` is enabled. Without one, the authenticator offers whatever
   * discoverable credentials it has for this site and the response says nothing about any account.
   */
  async authenticationOptions(userId: string | null): Promise<PasskeyLoginOptions> {
    const { config, adapter } = this.options;
    const passkeys = userId === null ? [] : await adapter.credentials.listPasskeys(userId);
    const options = await generateAuthenticationOptions({
      rpID: config.rpId,
      userVerification: config.userVerification,
      ...(passkeys.length > 0
        ? { allowCredentials: passkeys.map((passkey) => ({ id: passkey.credentialId, transports: passkey.transports })) }
        : {}),
    });
    const challengeId = randomToken(16);
    await adapter.ephemeral.set(`webauthn:authenticate:${challengeId}`, { challenge: options.challenge }, config.challengeTtlSec);
    return { challengeId, options };
  }

  /** Verifies a sign-in response. The challenge is consumed whether or not verification succeeds. */
  async verifyAuthentication(input: { challengeId: string; response: AuthenticationResponseJSON }): Promise<VerifiedPasskey> {
    const { config, adapter, clock } = this.options;
    const challenge = await this.takeChallenge('authenticate', input.challengeId);

    const credentialId = input.response?.id;
    if (typeof credentialId !== 'string' || credentialId.length === 0 || credentialId.length > MAX_ID_LENGTH) {
      throw new PasskeyError('PASSKEY_VERIFICATION_FAILED');
    }
    const passkey = await adapter.credentials.findPasskeyByCredentialId(credentialId);
    if (!passkey) throw new PasskeyError('PASSKEY_VERIFICATION_FAILED', { debug: 'Unknown credential id.' });

    try {
      const verification = await verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: config.origins,
        expectedRPID: config.rpId,
        requireUserVerification: config.userVerification === 'required',
        credential: {
          id: passkey.credentialId,
          publicKey: fromBase64Url(passkey.publicKey) as Uint8Array<ArrayBuffer>,
          counter: passkey.counter,
          transports: passkey.transports,
        },
      });
      if (!verification.verified) throw new Error('The assertion was not verified.');
      await adapter.credentials.updatePasskeyUsage(passkey.id, verification.authenticationInfo.newCounter, clock.now());
      return {
        userId: passkey.userId,
        passkeyId: passkey.id,
        userVerified: verification.authenticationInfo.userVerified,
      };
    } catch (cause) {
      // Includes a signature counter that went backwards, which suggests a cloned authenticator.
      const counter = cause instanceof Error && /counter/i.test(cause.message);
      throw new PasskeyError('PASSKEY_VERIFICATION_FAILED', { cause, ...(counter ? { debug: 'counter_regression' } : {}) });
    }
  }

  private async takeChallenge(kind: 'register', challengeId: string): Promise<{ userId: string; challenge: string }>;
  private async takeChallenge(kind: 'authenticate', challengeId: string): Promise<{ challenge: string }>;
  private async takeChallenge(kind: string, challengeId: string): Promise<{ userId?: string; challenge: string }> {
    if (typeof challengeId !== 'string' || challengeId.length === 0 || challengeId.length > 128) {
      throw new PasskeyError('PASSKEY_CHALLENGE_INVALID');
    }
    const stored = await this.options.adapter.ephemeral.take(`webauthn:${kind}:${challengeId}`);
    if (typeof stored !== 'object' || stored === null || Array.isArray(stored) || typeof stored.challenge !== 'string') {
      throw new PasskeyError('PASSKEY_CHALLENGE_INVALID');
    }
    return stored as { userId?: string; challenge: string };
  }
}
