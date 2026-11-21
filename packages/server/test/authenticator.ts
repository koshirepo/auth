/**
 * A software WebAuthn authenticator for tests.
 *
 * It does what a browser and a platform authenticator do together: creates ES256 key pairs, builds
 * attestation objects and assertions, and signs them. The server under test verifies the results
 * with the real `@simplewebauthn/server` code, so nothing about verification is mocked.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKED_UP = 0x10;
const FLAG_ATTESTED_CREDENTIAL = 0x40;

interface StoredCredential {
  id: Buffer;
  privateKey: KeyObject;
  rpId: string;
  userHandle: string;
  counter: number;
}

export interface AuthenticatorOptions {
  /** The origin of the page running the ceremony. */
  origin: string;
  /** Whether the authenticator checks a PIN or biometric. Default true. */
  userVerification?: boolean;
  /** Whether credentials are synced passkeys. Default true. */
  backedUp?: boolean;
}

export interface CeremonyOverrides {
  origin?: string;
  rpId?: string;
  challenge?: string;
  userVerified?: boolean;
  /** Force the signature counter instead of incrementing it. */
  counter?: number;
  /** Corrupt the signature. */
  tamperSignature?: boolean;
}

const b64url = (data: Buffer | Uint8Array) => Buffer.from(data).toString('base64url');
const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest();

export class SoftwareAuthenticator {
  readonly credentials = new Map<string, StoredCredential>();

  constructor(private readonly options: AuthenticatorOptions) {}

  private flags(userVerified: boolean, attested: boolean): number {
    let flags = FLAG_USER_PRESENT;
    if (userVerified) flags |= FLAG_USER_VERIFIED;
    if (this.options.backedUp !== false) flags |= FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP;
    if (attested) flags |= FLAG_ATTESTED_CREDENTIAL;
    return flags;
  }

  private authenticatorData(rpId: string, flags: number, counter: number, attestedCredentialData?: Buffer): Buffer {
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    return Buffer.concat([sha256(rpId), Buffer.from([flags]), counterBytes, attestedCredentialData ?? Buffer.alloc(0)]);
  }

  /** `navigator.credentials.create()`. */
  create(options: PublicKeyCredentialCreationOptionsJSON, overrides: CeremonyOverrides = {}): RegistrationResponseJSON {
    if (!options.pubKeyCredParams.some((param) => param.alg === -7)) throw new Error('The server did not offer ES256.');
    const rpId = overrides.rpId ?? options.rp.id ?? new URL(this.options.origin).hostname;
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const id = randomBytes(32);

    // COSE_Key for an EC2 P-256 key: kty 2, alg ES256 (-7), crv 1, then the coordinates.
    const coseKey = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(jwk.y as string, 'base64url'))],
      ]),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(id.length);
    const attestedCredentialData = Buffer.concat([Buffer.alloc(16), idLength, id, Buffer.from(coseKey)]);

    const userVerified = overrides.userVerified ?? this.options.userVerification !== false;
    const counter = overrides.counter ?? 0;
    const authData = this.authenticatorData(rpId, this.flags(userVerified, true), counter, attestedCredentialData);
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Uint8Array | Map<string, never>>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, never>()],
        ['authData', new Uint8Array(authData)],
      ]),
    );
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: overrides.challenge ?? options.challenge,
        origin: overrides.origin ?? this.options.origin,
        crossOrigin: false,
      }),
    );

    this.credentials.set(b64url(id), { id, privateKey, rpId, userHandle: options.user.id, counter });
    return {
      id: b64url(id),
      rawId: b64url(id),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  /** `navigator.credentials.get()`. Uses the first allowed credential, or any credential for the RP. */
  get(options: PublicKeyCredentialRequestOptionsJSON, overrides: CeremonyOverrides = {}): AuthenticationResponseJSON {
    const rpId = options.rpId ?? new URL(this.options.origin).hostname;
    const allowed = options.allowCredentials?.map((credential) => credential.id);
    const credential = [...this.credentials.values()].find(
      (candidate) => candidate.rpId === rpId && (allowed === undefined || allowed.includes(b64url(candidate.id))),
    );
    if (!credential) throw new Error('The authenticator has no credential for this request.');

    credential.counter = overrides.counter ?? credential.counter + 1;
    const userVerified = overrides.userVerified ?? this.options.userVerification !== false;
    const authData = this.authenticatorData(overrides.rpId ?? rpId, this.flags(userVerified, false), credential.counter);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: overrides.challenge ?? options.challenge,
        origin: overrides.origin ?? this.options.origin,
        crossOrigin: false,
      }),
    );
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), credential.privateKey);
    if (overrides.tamperSignature) signature[signature.length - 1] = (signature[signature.length - 1] as number) ^ 0xff;

    return {
      id: b64url(credential.id),
      rawId: b64url(credential.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: credential.userHandle,
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}
