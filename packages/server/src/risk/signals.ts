import type { DeviceRecord } from '../adapters/types.js';
import type { GeoLocator, RiskInput, RiskSignal } from './types.js';

const DAY_MS = 86_400_000;

function recentDevices(input: RiskInput, withinDays: number): DeviceRecord[] {
  const cutoff = input.now.getTime() - withinDays * DAY_MS;
  return input.devices.filter((device) => device.lastSeenAt.getTime() >= cutoff);
}

function expandIpv6(ip: string): string[] | null {
  const address = ip.split('%')[0] ?? ip;
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...(halves.length === 2 ? new Array<string>(missing).fill('0') : []), ...tail];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  return groups.map((group) => group.toLowerCase().replace(/^0+(?=.)/, ''));
}

/**
 * The network an address belongs to, for "has this user signed in from here before": the /24 of an
 * IPv4 address and the /48 of an IPv6 address. Unparseable input is compared as is.
 */
export function networkPrefix(ip: string): string {
  const v4 = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/i.exec(ip.trim());
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}`;
  const groups = expandIpv6(ip.trim());
  return groups ? groups.slice(0, 3).join(':') : ip.trim().toLowerCase();
}

/** Great-circle distance in kilometres. */
export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const toRad = (degrees: number) => (degrees * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/** Fires when the device key has not been seen for this user. Never fires on a first login. */
export function newDevice(options: { score?: number } = {}): RiskSignal {
  const score = options.score ?? 30;
  return (input) => {
    if (!input.deviceKey || input.devices.length === 0) return null;
    const known = input.devices.some((device) => device.deviceKey === input.deviceKey);
    return known ? null : { name: 'new_device', score };
  };
}

/** Fires when the IP is outside the networks of the user's recent successful logins. */
export function newNetwork(options: { score?: number; withinDays?: number } = {}): RiskSignal {
  const score = options.score ?? 15;
  const withinDays = options.withinDays ?? 90;
  return (input) => {
    if (!input.ip) return null;
    const knownIps = recentDevices(input, withinDays)
      .map((device) => device.lastIp)
      .filter((ip): ip is string => ip !== null);
    if (knownIps.length === 0) return null;
    const prefix = networkPrefix(input.ip);
    return knownIps.some((ip) => networkPrefix(ip) === prefix) ? null : { name: 'new_network', score };
  };
}

/**
 * Fires when the country differs from the user's recent logins, or when the distance from the
 * most recent login could not have been travelled in the time since.
 */
export function newLocation(options: {
  locate: GeoLocator;
  score?: number;
  withinDays?: number;
  /** Faster than this between two logins counts as impossible travel. Default 900 km/h. */
  maxSpeedKmh?: number;
}): RiskSignal {
  const score = options.score ?? 25;
  const withinDays = options.withinDays ?? 90;
  const maxSpeedKmh = options.maxSpeedKmh ?? 900;

  const signal: RiskSignal = (input) => {
    const here = input.location;
    if (!here) return null;
    const known = recentDevices(input, withinDays);
    if (known.length === 0) return null;

    if (here.country !== undefined) {
      const countries = known.map((device) => device.lastCountry).filter((country) => country !== null);
      if (countries.length > 0 && !countries.includes(here.country)) return { name: 'new_location', score };
    }

    const last = [...known].sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime())[0];
    if (
      last &&
      last.lastLatitude !== null &&
      last.lastLongitude !== null &&
      here.latitude !== undefined &&
      here.longitude !== undefined
    ) {
      const km = haversineKm(last.lastLatitude, last.lastLongitude, here.latitude, here.longitude);
      const hours = Math.max((input.now.getTime() - last.lastSeenAt.getTime()) / 3_600_000, 1 / 60);
      // Short distances are within the error of IP geolocation and are ignored.
      if (km > 100 && km / hours > maxSpeedKmh) return { name: 'new_location', score };
    }
    return null;
  };
  signal.locate = options.locate;
  return signal;
}

/** Scores recent failed sign-in attempts for the account or from the IP, whichever is higher. */
export function failedAttempts(options: { scorePerFailure?: number; max?: number } = {}): RiskSignal {
  const scorePerFailure = options.scorePerFailure ?? 10;
  const max = options.max ?? 40;
  return (input) => {
    const failures = Math.max(input.failures.account, input.failures.ip);
    if (failures <= 0) return null;
    return { name: 'failed_attempts', score: Math.min(max, failures * scorePerFailure) };
  };
}
