import { SETTINGS } from './config.js';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ALPHABET_LOWER = 'abcdefghijklmnopqrstuvwxyz0123456789';
const URLSAFE_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Чистая реализация SHA-256 для V8 isolate (без зависимости от Node.js crypto)
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(n, x) {
  return (x >>> n) | (x << (32 - n));
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  return new TextEncoder().encode(String(input));
}

export function sha256Bytes(msgInput) {
  const msg = toBytes(msgInput);
  const bitLen = msg.length * 8;
  const padLen = ((msg.length + 9 + 63) & ~63);
  const padded = new Uint8Array(padLen);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

export function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function sha256Hex(msgInput) {
  return bytesToHex(sha256Bytes(msgInput));
}

export function hmacSha256Bytes(keyInput, msgInput) {
  let key = toBytes(keyInput);
  const msg = toBytes(msgInput);
  if (key.length > 64) {
    key = sha256Bytes(key);
  }
  const kPad = new Uint8Array(64);
  kPad.set(key);

  const ipad = new Uint8Array(64 + msg.length);
  const opad = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    ipad[i] = kPad[i] ^ 0x36;
    opad[i] = kPad[i] ^ 0x5c;
  }
  ipad.set(msg, 64);
  const innerHash = sha256Bytes(ipad);
  opad.set(innerHash, 64);
  return sha256Bytes(opad);
}

export function hmacSha256Hex(keyInput, msgInput) {
  return bytesToHex(hmacSha256Bytes(keyInput, msgInput));
}

export function nowTs() {
  return Math.floor(Date.now() / 1000);
}

export function daysFromNow(days) {
  return nowTs() + Number(days) * 86400;
}

export function toXuiMs(timestampS) {
  return Number(timestampS) * 1000;
}

export function hashSecret(value) {
  return hmacSha256Hex(SETTINGS.serverPepper, String(value));
}

export function hashToken(token, purpose) {
  return hmacSha256Hex(SETTINGS.serverPepper, `${purpose}\x00${token}`);
}

export function constantTimeEquals(a, b) {
  if (a == null || b == null) return false;
  const ba = toBytes(a);
  const bb = toBytes(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i++) {
    diff |= ba[i] ^ bb[i];
  }
  return diff === 0;
}

function randomBytes(size) {
  const arr = new Uint8Array(size);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(arr);
    return arr;
  }
  for (let i = 0; i < size; i++) {
    arr[i] = Math.floor(Math.random() * 256);
  }
  return arr;
}

function randomChoice(alphabet, length) {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

export function randomCode(prefix, groups = [4, 4, 4]) {
  const chunks = groups.map((size) => randomChoice(ALPHABET, size));
  return `${prefix}-${chunks.join('-')}`;
}

export function maskedCode(code) {
  if (!code) return '';
  const str = String(code);
  if (str.includes('-')) {
    return `${str.split('-')[0]}-...`;
  }
  if (str.length <= 4) return `${str.slice(0, 1)}...`;
  return `${str.slice(0, 3)}...`;
}

export function publicId(prefix, size = 12) {
  return `${prefix}_${randomChoice(ALPHABET_LOWER, size)}`;
}

export function orderToProfileAlias(orderPubId, suffix = '') {
  const str = String(orderPubId);
  const cleanId = str.startsWith('ord_') ? str.slice(4) : str;
  const base = `anon-${cleanId}`;
  return suffix ? `${base}-${suffix}` : base;
}

export function randomAlias(prefix = 'anon', size = 12) {
  return `${prefix}-${randomChoice(ALPHABET_LOWER, size)}`;
}

export function randomSubscriptionId(size = 16) {
  return randomChoice(ALPHABET_LOWER, size);
}

export function randomWebToken() {
  return randomChoice(URLSAFE_B64, 32);
}

export function normalizeUsername(username) {
  return String(username || '')
    .trim()
    .replace(/^@+/, '')
    .toLowerCase();
}
