// SPDX-License-Identifier: Apache-2.0
// Port of src/privacy_gate/guard/validators.py: the checks a regex cannot make. Each takes the span text exactly
// as matched and returns a boolean. IP parsing follows Python's `ipaddress` rules, which the conformance suite
// was generated with (an IPv4 octet with a leading zero is invalid; IPv6 allows one `::`).

export const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22,
  CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22,
  GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30,
  KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31,
  MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31, SE: 24,
  SI: 19, SK: 24, SM: 27, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

const digits = (text: string): string => text.replace(/[^0-9]/g, "");

/** Payment card: 13 to 19 digits whose Luhn sum is a multiple of ten. */
export function luhn(text: string): boolean {
  const number = digits(text);
  if (number.length < 13 || number.length > 19) return false;
  let total = 0;
  for (let position = 0; position < number.length; position++) {
    let value = number.charCodeAt(number.length - 1 - position) - 48;
    if (position % 2 === 1) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    total += value;
  }
  return total % 10 === 0;
}

/** IBAN: known country, that country's length, and ISO 7064 mod 97-10 equal to 1. */
export function iban_mod97(text: string): boolean {
  // Python's str.isspace() set for the characters a match can hold (the pattern allows ASCII space only).
  const compact = text.replace(/[\t\n\v\f\r .-]+/g, "").toUpperCase();
  if (compact.length < 5 || !/^[A-Z0-9]+$/.test(compact)) return false;
  if (IBAN_LENGTHS[compact.slice(0, 2)] !== compact.length) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const value = parseInt(ch, 36);
    remainder = (value > 9 ? remainder * 100 + value : remainder * 10 + value) % 97;
  }
  return remainder === 1;
}

/** NHS number: ten digits, weights 10 to 2, check digit by modulus 11; a check of 10 was never issued. */
export function nhs_mod11(text: string): boolean {
  const number = digits(text);
  if (number.length !== 10) return false;
  let total = 0;
  for (let i = 0; i < 9; i++) total += (10 - i) * (number.charCodeAt(i) - 48);
  let check = 11 - (total % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === number.charCodeAt(9) - 48;
}

/** US SSN: area not 000, 666 or 900-999, group not 00, serial not 0000. */
export function us_ssn_area(text: string): boolean {
  const number = digits(text);
  if (number.length !== 9) return false;
  const area = Number(number.slice(0, 3));
  const group = Number(number.slice(3, 5));
  const serial = Number(number.slice(5));
  if (area === 0 || area === 666 || area >= 900) return false;
  return group !== 0 && serial !== 0;
}

/**
 * Four decimal octets, 0-255, at most three digits each. Brackets and spaces around the dots
 * (`192[.]168[.]1[.]20`) are dropped and a zero-padded octet is decimal, as in the Python validator.
 */
function parseIPv4(text: string): number[] | null {
  const parts = text.replace(/[[\]() ]/g, "").split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }
  return octets;
}

/** Python's IPv6Address parser for the hex-and-colon form (the rule's pattern never matches a dotted tail). */
function parseIPv6(text: string): number[] | null {
  const parts = text.split(":");
  if (parts.length < 3 || parts.length > 9) return null;
  let skip = -1;
  for (let i = 1; i < parts.length - 1; i++) {
    if (parts[i] === "") {
      if (skip !== -1) return null; // at most one "::"
      skip = i;
    }
  }
  let hi: number;
  let lo: number;
  if (skip !== -1) {
    hi = skip;
    lo = parts.length - skip - 1;
    if (parts[0] === "") {
      hi -= 1;
      if (hi) return null; // a leading ":" only as part of "::"
    }
    if (parts[parts.length - 1] === "") {
      lo -= 1;
      if (lo) return null; // a trailing ":" only as part of "::"
    }
    if (8 - (hi + lo) < 1) return null;
  } else {
    if (parts.length !== 8 || parts[0] === "" || parts[7] === "") return null;
    hi = parts.length;
    lo = 0;
  }
  const hextets: number[] = [];
  const parse = (h: string): number | null => (/^[0-9a-fA-F]{1,4}$/.test(h) ? parseInt(h, 16) : null);
  for (let i = 0; i < hi; i++) {
    const v = parse(parts[i]!);
    if (v === null) return null;
    hextets.push(v);
  }
  for (let i = 0; i < 8 - hi - lo; i++) hextets.push(0);
  for (let i = parts.length - lo; i < parts.length; i++) {
    const v = parse(parts[i]!);
    if (v === null) return null;
    hextets.push(v);
  }
  return hextets;
}

/** A private (RFC 1918), link-local or CGNAT IPv4 address; a last octet of 0 names a network, not a machine. */
export function private_ipv4(text: string): boolean {
  const o = parseIPv4(text);
  if (o === null || o[3] === 0) return false;
  const [a, b] = o as [number, number];
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

/** A unique-local (fc00::/7) or link-local (fe80::/10) IPv6 address. */
export function private_ipv6(text: string): boolean {
  const h = parseIPv6(text);
  if (h === null) return false;
  const first = h[0]!;
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

/** A telephone number: 10 to 15 digits, and not one digit repeated (a placeholder). */
export function phone_digits(text: string): boolean {
  const number = digits(text);
  if (number.length < 10 || number.length > 15) return false;
  return new Set(number).size > 1;
}

/** At least one ASCII letter and one digit: a stated password, not the next word of the sentence. */
export function letter_and_digit(text: string): boolean {
  return /[A-Za-z]/.test(text) && /[0-9]/.test(text);
}

export const VALIDATORS: Readonly<Record<string, (text: string) => boolean>> = {
  luhn,
  iban_mod97,
  nhs_mod11,
  us_ssn_area,
  private_ipv4,
  private_ipv6,
  phone_digits,
  letter_and_digit,
};
