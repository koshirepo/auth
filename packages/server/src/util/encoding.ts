import { base64url } from 'jose';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function toBase64Url(bytes: Uint8Array): string {
  return base64url.encode(bytes);
}

/** Decodes base64url, and also standard base64 with or without padding. Throws on other input. */
export function fromBase64Url(text: string): Uint8Array {
  const normalised = text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(normalised)) throw new TypeError('Input is not base64url.');
  return base64url.decode(normalised);
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32 without padding. Authenticator apps expect TOTP secrets in this form. */
export function toBase32(bytes: Uint8Array): string {
  let output = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Decodes base32, ignoring case, padding, spaces and dashes. Throws on any other character. */
export function fromBase32(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  const output = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of clean) {
    const digit = BASE32_ALPHABET.indexOf(char);
    if (digit === -1) throw new TypeError('Input is not base32.');
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output[index++] = (value >>> bits) & 0xff;
      value &= (1 << bits) - 1;
    }
  }
  return output;
}
