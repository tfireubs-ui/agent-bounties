// Agent Bounties Platform — Cloudflare Workers + D1
// AIBTC-verified agents post bounties, anyone can claim and complete them.
// Payment is direct sBTC transfer, verified on-chain via Hiro API.

import * as secp from '@noble/secp256k1';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import {
  Transaction,
  RawTx,
  RawWitness,
  p2wpkh,
  p2pkh,
  Script,
  SigHash,
  NETWORK as BTC_NETWORK,
} from '@scure/btc-signer';

interface Env {
  DB: D1Database;
  GITHUB_TOKEN?: string;
}

// ─── Admin ───────────────────────────────────────────────────────────────────

const ADMIN_BTC_ADDRESS = 'bc1qqaxq5vxszt0lzmr9gskv4lcx7jzrg772s4vxpp';

// ─── CORS ────────────────────────────────────────────────────────────────────

const WRITE_ALLOWED_ORIGINS: readonly string[] = [
  'https://bounty.drx4.xyz',
];

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function resolveCorsOrigin(requestOrigin: string | null, isWrite: boolean): string | null {
  if (!isWrite) return '*';
  // No Origin header = server-to-server (agents, curl) — allow with no CORS headers
  if (!requestOrigin) return 'null';
  if ((WRITE_ALLOWED_ORIGINS as string[]).includes(requestOrigin)) return requestOrigin;
  if (/^https?:\/\/localhost(:\d+)?$/.test(requestOrigin)) return requestOrigin;
  if (/^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(requestOrigin)) return requestOrigin;
  return null;
}

function corsHeaders(origin: string, vary = false): HeadersInit {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (vary) headers['Vary'] = 'Origin';
  return headers;
}

function json(data: unknown, status = 200, corsOrigin: string | null = '*'): Response {
  if (corsOrigin === null) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const vary = corsOrigin !== '*';
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(corsOrigin, vary) },
  });
}

// ─── Input Validation ────────────────────────────────────────────────────────

function isValidBtcAddress(addr: string): boolean {
  if (addr.startsWith('bc1') || addr.startsWith('BC1')) {
    if (addr !== addr.toLowerCase()) return false;
    return /^bc1[a-z0-9]{6,87}$/.test(addr);
  }
  return /^[13][a-zA-HJ-NP-Z0-9]{25,34}$/.test(addr);
}

function isValidStxAddress(addr: string): boolean {
  return /^(SP|SM)[A-Z0-9]{38}$/.test(addr);
}

function isValidTxHash(hash: string): boolean {
  return /^(0x)?[a-f0-9]{64}$/.test(hash);
}

function normalizeTxHash(hash: string): string {
  return hash.startsWith('0x') ? hash.slice(2) : hash;
}

const MAX_TITLE = 200;
const MAX_DESCRIPTION = 2000;
const MAX_TAGS = 500;
const MAX_MESSAGE = 1000;
const MAX_PROOF_URL = 500;
const MAX_GITHUB_URL = 500;
const GITHUB_ISSUE_URL_RE = /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/issues\/\d+$/;
const MAX_REVIEWER_NOTES = 1000;

const MAX_BODY_SIZE = 1024 * 1024; // 1MB
const TOO_LARGE_RESPONSE = JSON.stringify({ error: 'Request body too large' });

async function readBodyWithSizeCheck(request: Request): Promise<{ error: Response } | { text: string }> {
  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader !== null) {
    const declared = parseInt(contentLengthHeader, 10);
    if (!isNaN(declared) && declared > MAX_BODY_SIZE) {
      return { error: new Response(TOO_LARGE_RESPONSE, {
        status: 413,
        headers: { 'Content-Type': 'application/json' }
      }) };
    }
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_SIZE) {
    return { error: new Response(TOO_LARGE_RESPONSE, {
      status: 413,
      headers: { 'Content-Type': 'application/json' }
    }) };
  }
  return { text };
}

// ─── D1 Helper ───────────────────────────────────────────────────────────────

async function dbRun(stmt: D1PreparedStatement): Promise<D1Result> {
  const result = await stmt.run();
  if (!result.success) {
    throw new Error('Database operation failed');
  }
  return result;
}

// ─── BIP-137 Signature Verification ─────────────────────────────────────────

function encodeVarint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) { const b = new Uint8Array(3); b[0] = 0xfd; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; return b; }
  const b = new Uint8Array(5); b[0] = 0xfe; for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff; return b;
}

function bitcoinMessageHash(message: string): Uint8Array {
  const prefix = '\x18Bitcoin Signed Message:\n';
  const prefixBytes = new TextEncoder().encode(prefix);
  const msgBytes = new TextEncoder().encode(message);
  const msgLen = encodeVarint(msgBytes.length);
  const buf = new Uint8Array(prefixBytes.length + msgLen.length + msgBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(msgLen, prefixBytes.length);
  buf.set(msgBytes, prefixBytes.length + msgLen.length);
  return sha256(sha256(buf));
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32Encode(hrp: string, data: number[]): string {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const expand = [...Array.from(hrp, c => c.charCodeAt(0) >> 5), 0, ...Array.from(hrp, c => c.charCodeAt(0) & 31)];
  const values = [...expand, ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0, bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function pubkeyToBech32(pubkey: Uint8Array): string {
  const hash = ripemd160(sha256(pubkey));
  const words = [0, ...convertBits(hash, 8, 5, true)];
  return bech32Encode('bc', words);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58CheckEncode(version: number, payload: Uint8Array): string {
  const data = new Uint8Array(1 + payload.length + 4);
  data[0] = version;
  data.set(payload, 1);
  const checksum = sha256(sha256(data.subarray(0, 1 + payload.length)));
  data.set(checksum.subarray(0, 4), 1 + payload.length);
  let num = 0n;
  for (const byte of data) num = num * 256n + BigInt(byte);
  let encoded = '';
  while (num > 0n) {
    encoded = BASE58_ALPHABET[Number(num % 58n)] + encoded;
    num = num / 58n;
  }
  for (const byte of data) {
    if (byte !== 0) break;
    encoded = '1' + encoded;
  }
  return encoded;
}

function pubkeyToP2PKH(pubkey: Uint8Array): string {
  const hash = ripemd160(sha256(pubkey));
  return base58CheckEncode(0x00, hash);
}

function pubkeyToP2SH_P2WPKH(pubkey: Uint8Array): string {
  const keyHash = ripemd160(sha256(pubkey));
  const redeemScript = new Uint8Array(22);
  redeemScript[0] = 0x00;
  redeemScript[1] = 0x14;
  redeemScript.set(keyHash, 2);
  const scriptHash = ripemd160(sha256(redeemScript));
  return base58CheckEncode(0x05, scriptHash);
}

function deriveAddress(pubkey: Uint8Array, header: number): string {
  if (header >= 39) return pubkeyToBech32(pubkey);
  if (header >= 35) return pubkeyToP2SH_P2WPKH(pubkey);
  return pubkeyToP2PKH(pubkey);
}

async function verifyBip137(signature: string, message: string, expectedAddress: string): Promise<string | null> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  } catch { return 'Invalid signature: not valid base64'; }

  if (sigBytes.length !== 65) return `Invalid signature: expected 65 bytes, got ${sigBytes.length}`;

  const header = sigBytes[0];
  if (header < 27 || header > 42) return `Invalid signature header byte: ${header}`;

  const recoveryId = (header - 27) & 3;
  const compressed = header >= 31;

  const r = sigBytes.slice(1, 33);
  const s = sigBytes.slice(33, 65);
  const sig = new secp.Signature(
    BigInt('0x' + Array.from(r, b => b.toString(16).padStart(2, '0')).join('')),
    BigInt('0x' + Array.from(s, b => b.toString(16).padStart(2, '0')).join(''))
  ).addRecoveryBit(recoveryId);

  const msgHash = bitcoinMessageHash(message);

  let pubkey: Uint8Array;
  try {
    const point = sig.recoverPublicKey(msgHash);
    pubkey = point.toRawBytes(compressed);
  } catch { return 'Signature recovery failed: invalid signature for this message'; }

  const derivedAddress = deriveAddress(pubkey, header).toLowerCase();
  const expectedAddressNorm = expectedAddress.toLowerCase();
  if (derivedAddress !== expectedAddressNorm) {
    return `Signature mismatch: recovered ${derivedAddress}, expected ${expectedAddressNorm}`;
  }

  return null;
}

// ─── BIP-322 Signature Verification (P2WPKH / bc1q) ─────────────────────────
// Uses @scure/btc-signer for transaction construction and sighash computation,
// matching the reference implementation at aibtcdev-landing-page/lib/bitcoin-verify.ts

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Convert DER-encoded ECDSA signature to compact (64-byte r||s) format.
 * Strips leading 0x00 padding and left-pads to 32 bytes each.
 */
function parseDERSignature(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error('parseDERSignature: expected 0x30 header');
  let pos = 2;
  if (der[pos] !== 0x02) throw new Error('parseDERSignature: expected 0x02 for r');
  pos++;
  const rLen = der[pos++];
  const rRaw = der.slice(pos, pos + rLen);
  pos += rLen;
  if (der[pos] !== 0x02) throw new Error('parseDERSignature: expected 0x02 for s');
  pos++;
  const sLen = der[pos++];
  const sRaw = der.slice(pos, pos + sLen);

  // Strip leading 0x00 padding (added when high bit is set to keep integer positive)
  const rBytes = rRaw[0] === 0x00 ? rRaw.slice(1) : rRaw;
  const sBytes = sRaw[0] === 0x00 ? sRaw.slice(1) : sRaw;

  const compact = new Uint8Array(64);
  compact.set(rBytes, 32 - rBytes.length); // left-pad r
  compact.set(sBytes, 64 - sBytes.length); // left-pad s
  return compact;
}

/**
 * BIP-322 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 * where tag = "BIP0322-signed-message"
 *
 * Per the BIP-322 spec, message bytes are concatenated directly — there is no
 * varint length prefix before the message. The tagged-hash construction is:
 *   tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 * The varint is a Bitcoin script/wire encoding convention and does NOT apply here.
 */
function bip322TaggedHash(message: string): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode('BIP0322-signed-message'));
  const msgBytes = new TextEncoder().encode(message);
  return sha256(concatBytes(tagHash, tagHash, msgBytes));
}

/**
 * Build BIP-322 to_spend virtual transaction and return its txid.
 * Uses RawTx.encode() from @scure/btc-signer for correct serialization.
 */
function bip322BuildToSpendTxId(message: string, scriptPubKey: Uint8Array): Uint8Array {
  const msgHash = bip322TaggedHash(message);
  const scriptSig = concatBytes(new Uint8Array([0x00, 0x20]), msgHash);

  const rawTx = RawTx.encode({
    version: 0,
    inputs: [{
      txid: new Uint8Array(32),
      index: 0xffffffff,
      finalScriptSig: scriptSig,
      sequence: 0,
    }],
    outputs: [{
      amount: BigInt(0),
      script: scriptPubKey,
    }],
    lockTime: 0,
  });

  // txid = doubleSHA256 in reversed byte order (display format, expected by btc-signer)
  return doubleSha256(rawTx).reverse();
}

async function verifyBip322P2WPKH(signatureB64: string, message: string, expectedAddress: string): Promise<string | null> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
  } catch { return 'Invalid BIP-322 signature: not valid base64'; }

  // Decode witness stack using @scure/btc-signer
  let witnessItems: Uint8Array[];
  try {
    witnessItems = RawWitness.decode(sigBytes);
  } catch { return 'Invalid BIP-322 witness encoding'; }

  if (witnessItems.length !== 2) return `Expected 2 witness items (P2WPKH), got ${witnessItems.length}`;

  const ecdsaSigWithHashtype = witnessItems[0];
  const pubkeyBytes = witnessItems[1];

  if (pubkeyBytes.length !== 33) return `Expected 33-byte compressed pubkey, got ${pubkeyBytes.length}`;

  // Derive scriptPubKey and address from witness pubkey
  const p2wpkhResult = p2wpkh(pubkeyBytes, BTC_NETWORK);
  const scriptPubKey = p2wpkhResult.script;
  const derivedAddress = p2wpkhResult.address;

  if (derivedAddress?.toLowerCase() !== expectedAddress.toLowerCase()) {
    return `BIP-322 pubkey mismatch: derived ${derivedAddress}, expected ${expectedAddress}`;
  }

  // Build to_spend txid
  const toSpendTxid = bip322BuildToSpendTxId(message, scriptPubKey);

  // Build (unsigned) to_sign transaction for sighash computation
  const toSignTx = new Transaction({ version: 0, lockTime: 0, allowUnknownOutputs: true });
  toSignTx.addInput({
    txid: toSpendTxid,
    index: 0,
    sequence: 0,
    witnessUtxo: { amount: BigInt(0), script: scriptPubKey },
  });
  toSignTx.addOutput({ script: Script.encode(['RETURN']), amount: BigInt(0) });

  // Compute BIP143 witness-v0 sighash using btc-signer
  const scriptCode = p2pkh(pubkeyBytes).script;
  const sighash = toSignTx.preimageWitnessV0(0, scriptCode, SigHash.ALL, BigInt(0));

  // Strip hashtype byte, convert DER to compact format
  const derSig = ecdsaSigWithHashtype.slice(0, -1);
  const compactSig = parseDERSignature(derSig);

  // Verify ECDSA using @noble/curves (matches btc-signer internals)
  const valid = secp256k1.verify(compactSig, sighash, pubkeyBytes, { prehash: false });
  if (!valid) return 'BIP-322 ECDSA verification failed';

  return null; // verified
}

// ─── Unified Signature Verification ──────────────────────────────────────────

async function verifySignature(signatureB64: string, message: string, expectedAddress: string): Promise<string | null> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
  } catch { return 'Invalid signature: not valid base64'; }

  if (sigBytes.length === 65) {
    return verifyBip137(signatureB64, message, expectedAddress);
  }
  // BIP-322 witness (variable length, starts with item count)
  return verifyBip322P2WPKH(signatureB64, message, expectedAddress);
}

// ─── Signature Replay Protection ─────────────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}

async function recordSignatureUse(db: D1Database, sigHash: string): Promise<string | null> {
  const result = await db
    .prepare('INSERT OR IGNORE INTO used_signatures (sig_hash) VALUES (?)')
    .bind(sigHash)
    .run();
  if (result.meta.rows_written === 0) {
    return 'Signature already used — replay detected';
  }
  return null;
}

async function cleanupExpiredSignatures(db: D1Database): Promise<void> {
  await db
    .prepare("DELETE FROM used_signatures WHERE used_at < datetime('now', '-1 day')")
    .run();
}

// ─── IP-Based Rate Limiting ──────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_SECONDS = 300;
const RATE_LIMIT_MAX_REQUESTS = 10;

function getClientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ?? 'unknown';
}

function endpointKey(pathname: string): string {
  const parts = pathname.split('/').filter(Boolean);
  return '/' + parts.slice(0, 2).join('/');
}

async function checkRateLimit(db: D1Database, request: Request): Promise<Response | null> {
  const ip = getClientIp(request);
  const endpoint = endpointKey(new URL(request.url).pathname);
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % RATE_LIMIT_WINDOW_SECONDS);
  const windowStartIso = new Date(windowStart * 1000).toISOString();

  await db
    .prepare('DELETE FROM rate_limits WHERE window_start < ?')
    .bind(windowStartIso)
    .run();

  await db
    .prepare(
      `INSERT INTO rate_limits (ip, endpoint, window_start, request_count)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(ip, endpoint, window_start) DO UPDATE
         SET request_count = request_count + 1`
    )
    .bind(ip, endpoint, windowStartIso)
    .run();

  const row = await db
    .prepare('SELECT request_count FROM rate_limits WHERE ip = ? AND endpoint = ? AND window_start = ?')
    .bind(ip, endpoint, windowStartIso)
    .first<{ request_count: number }>();

  const count = row?.request_count ?? 1;
  if (count > RATE_LIMIT_MAX_REQUESTS) {
    const windowEnd = windowStart + RATE_LIMIT_WINDOW_SECONDS;
    const retryAfter = Math.max(0, windowEnd - now);
    return new Response(JSON.stringify({ error: 'Too many requests — try again later' }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
        'X-RateLimit-Limit': String(RATE_LIMIT_MAX_REQUESTS),
        'X-RateLimit-Window': `${RATE_LIMIT_WINDOW_SECONDS}s`,
      },
    });
  }

  return null;
}

async function cleanupExpiredRateLimits(db: D1Database): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const currentWindowStart = now - (now % RATE_LIMIT_WINDOW_SECONDS);
  const currentWindowStartIso = new Date(currentWindowStart * 1000).toISOString();
  await db
    .prepare('DELETE FROM rate_limits WHERE window_start < ?')
    .bind(currentWindowStartIso)
    .run();
}

// ─── AIBTC Identity Verification ─────────────────────────────────────────────

interface AibtcAgent {
  level: number;
  display_name: string | null;
  btc_address: string | null;
}

async function verifyAibtcAgent(db: D1Database, stxAddress: string): Promise<AibtcAgent | null> {
  // Check D1 cache first (1hr TTL)
  const cached = await db
    .prepare("SELECT level, display_name, btc_address, verified_at FROM aibtc_cache WHERE stx_address = ? AND verified_at > datetime('now', '-1 hour')")
    .bind(stxAddress)
    .first<{ level: number; display_name: string | null; btc_address: string | null }>();

  if (cached) {
    return { level: cached.level, display_name: cached.display_name, btc_address: cached.btc_address };
  }

  // Call AIBTC API
  const resp = await fetch(`https://aibtc.com/api/verify/${stxAddress}`);
  if (!resp.ok) {
    if (resp.status === 404) return null; // genuinely not registered
    throw new Error(`AIBTC API error: ${resp.status} ${await resp.text()}`);
  }

  const data = await resp.json() as {
    registered?: boolean;
    level?: number;
    agent?: {
      stxAddress?: string;
      btcAddress?: string;
      displayName?: string;
      bnsName?: string;
    };
  };

  if (!data.registered) return null;

  const level = data.level ?? 0;
  const agent = data.agent;
  const display_name = agent?.displayName || agent?.bnsName || null;
  const btc_address = agent?.btcAddress || null;

  // Cache the result
  await db
    .prepare(
      `INSERT INTO aibtc_cache (stx_address, level, display_name, btc_address, verified_at)
       VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT(stx_address) DO UPDATE SET
         level = excluded.level,
         display_name = excluded.display_name,
         btc_address = excluded.btc_address,
         verified_at = excluded.verified_at`
    )
    .bind(stxAddress, level, display_name, btc_address)
    .run();

  return { level, display_name, btc_address };
}

// ─── On-Chain Payment Verification (sBTC via Hiro API) ───────────────────────

const SBTC_CONTRACT = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token';

interface PaymentVerification {
  verified: boolean;
  error?: string;
  amount_sats?: number;
}

async function verifyPayment(
  txHash: string,
  expectedFrom: string,
  expectedTo: string,
  expectedAmountSats: number
): Promise<PaymentVerification> {
  const normalizedHash = normalizeTxHash(txHash);

  try {
    const resp = await fetch(`https://api.hiro.so/extended/v1/tx/0x${normalizedHash}`);
    if (!resp.ok) {
      return { verified: false, error: `Hiro API returned ${resp.status}` };
    }

    const tx = await resp.json() as {
      tx_status: string;
      tx_type: string;
      sender_address: string;
      contract_call?: {
        contract_id: string;
        function_name: string;
        function_args?: Array<{
          name: string;
          repr: string;
          type: string;
        }>;
      };
    };

    if (tx.tx_status !== 'success') {
      return { verified: false, error: `Transaction status: ${tx.tx_status}` };
    }

    if (tx.tx_type !== 'contract_call') {
      return { verified: false, error: 'Not a contract call transaction' };
    }

    if (tx.contract_call?.contract_id !== SBTC_CONTRACT) {
      return { verified: false, error: `Wrong contract: ${tx.contract_call?.contract_id}` };
    }

    if (tx.contract_call?.function_name !== 'transfer') {
      return { verified: false, error: `Wrong function: ${tx.contract_call?.function_name}` };
    }

    // Verify sender
    if (tx.sender_address !== expectedFrom) {
      return { verified: false, error: `Wrong sender: ${tx.sender_address}, expected ${expectedFrom}` };
    }

    // Parse function args to verify recipient and amount
    const args = tx.contract_call?.function_args;
    if (!args) {
      return { verified: false, error: 'No function args found' };
    }

    // sBTC transfer args: amount, sender, recipient
    const amountArg = args.find(a => a.name === 'amount');
    const recipientArg = args.find(a => a.name === 'recipient');

    if (!amountArg || !recipientArg) {
      return { verified: false, error: 'Missing amount or recipient in function args' };
    }

    // Parse amount from Clarity repr (e.g., "u100000")
    const amountMatch = amountArg.repr.match(/^u(\d+)$/);
    if (!amountMatch) {
      return { verified: false, error: `Cannot parse amount: ${amountArg.repr}` };
    }
    const actualAmount = parseInt(amountMatch[1], 10);

    // Parse recipient from Clarity repr (e.g., "'SP...")
    const recipientMatch = recipientArg.repr.match(/^'?(SP[A-Z0-9]+|SM[A-Z0-9]+)$/);
    if (!recipientMatch) {
      return { verified: false, error: `Cannot parse recipient: ${recipientArg.repr}` };
    }
    const actualRecipient = recipientMatch[1];

    if (actualRecipient !== expectedTo) {
      return { verified: false, error: `Wrong recipient: ${actualRecipient}, expected ${expectedTo}` };
    }

    if (actualAmount < expectedAmountSats) {
      return { verified: false, error: `Insufficient amount: ${actualAmount} < ${expectedAmountSats}` };
    }

    return { verified: true, amount_sats: actualAmount };
  } catch (err: any) {
    return { verified: false, error: `Verification failed: ${err.message}` };
  }
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

// Message format: "agent-bounties | {action} | {btc} | {resource} | {ts}"
interface AuthResult {
  btcAddress: string;
  stxAddress?: string;
  error?: string;
}

async function validateAuth(
  body: any,
  db: D1Database,
  action: string,
  resource: string
): Promise<{ error: string; expected_message?: string; signing_format?: string; hint?: string } | { btcAddress: string; stxAddress?: string }> {
  if (!body.btc_address) return { error: 'Required: btc_address' };
  if (!isValidBtcAddress(body.btc_address)) return { error: 'Invalid btc_address' };
  if (body.stx_address && !isValidStxAddress(body.stx_address)) return { error: 'Invalid stx_address' };
  if (!body.signature) return { error: 'Required: signature (BIP-137 or BIP-322)' };
  if (!body.timestamp) return { error: 'Required: timestamp (ISO 8601)' };

  if (typeof body.signature !== 'string' || body.signature.length < 10 || body.signature.length > 500) {
    return { error: 'Invalid signature format' };
  }

  const ts = new Date(body.timestamp).getTime();
  if (isNaN(ts)) return { error: 'Invalid timestamp format' };
  const drift = Math.abs(Date.now() - ts);
  if (drift > 300_000) return { error: 'Timestamp expired (must be within 300 seconds)' };

  const expectedMessage = `agent-bounties | ${action} | ${body.btc_address} | ${resource} | ${body.timestamp}`;
  const sigErr = await verifySignature(body.signature, expectedMessage, body.btc_address);
  if (sigErr) return {
    error: `Signature verification failed: ${sigErr}`,
    expected_message: expectedMessage,
    signing_format: 'agent-bounties | {action} | {btc_address} | {resource} | {timestamp}',
    hint: `Sign exactly this string with btc_sign_message: "${expectedMessage}"`,
  };

  // Replay protection
  await cleanupExpiredSignatures(db);
  const replayErr = await recordSignatureUse(db, await sha256Hex(body.signature));
  if (replayErr) return { error: replayErr };

  return { btcAddress: body.btc_address, stxAddress: body.stx_address };
}

// ─── Ensure Agent Row ────────────────────────────────────────────────────────

async function ensureAgent(db: D1Database, stxAddress: string, btcAddress?: string, displayName?: string, level?: number) {
  await dbRun(db
    .prepare(
      `INSERT INTO agents (stx_address, btc_address, display_name, aibtc_level) VALUES (?, ?, ?, ?)
       ON CONFLICT(stx_address) DO UPDATE SET
         btc_address = COALESCE(excluded.btc_address, agents.btc_address),
         display_name = COALESCE(excluded.display_name, agents.display_name),
         aibtc_level = CASE WHEN excluded.aibtc_level > agents.aibtc_level THEN excluded.aibtc_level ELSE agents.aibtc_level END,
         updated_at = datetime('now')`
    )
    .bind(stxAddress, btcAddress || null, displayName || null, level ?? 0)
  );
}

// ─── Security Headers ─────────────────────────────────────────────────────

function withSecurityHeaders(response: Response, nonce?: string): Response {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  headers.set('X-XSS-Protection', '0');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  if (response.headers.get('Content-Type')?.includes('text/html') && nonce) {
    headers.set('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'none'`);
  }
  return new Response(response.body, { status: response.status, headers });
}

// ─── HTML Templates ───────────────────────────────────────────────────────

const CSS_VARS = `--gold:#f7931a;--gold-light:#fbb03b;--gold-dim:#c06b00;--parchment:#e0dcd4;--parchment-dim:#a89b80;--bg:#0d1117;--bg-card:#161b22;--border:#30363d;--border-light:#484f58;--green:#5a9e3e;--red:#9e3e3e`;

function baseCSS(nonce: string): string {
  return `<style nonce="${nonce}">
*{margin:0;padding:0;box-sizing:border-box}
:root{${CSS_VARS}}
body{background:var(--bg);color:var(--parchment);font-family:'Poppins',sans-serif;font-size:0.95rem;line-height:1.7;overflow-x:hidden}
body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:radial-gradient(ellipse at 50% 0%,rgba(247,147,26,0.03) 0%,transparent 60%);pointer-events:none;z-index:0}
main{max-width:1280px;margin:0 auto;padding:1rem 2rem;position:relative;z-index:1}
a{color:var(--gold);text-decoration:none;transition:color 0.3s,text-shadow 0.3s}
a:hover{color:var(--gold-light);text-shadow:0 0 8px rgba(247,147,26,0.3)}
h1{font-family:'Poppins',sans-serif;font-size:1.8rem;font-weight:900;color:var(--gold);letter-spacing:0.15em;text-align:center;margin-bottom:0.15rem;text-shadow:0 0 40px rgba(247,147,26,0.15)}
.subtitle{font-family:'Poppins',sans-serif;font-size:0.8rem;font-weight:400;color:var(--parchment-dim);letter-spacing:0.2em;text-transform:uppercase;text-align:center;margin-bottom:0.6rem}
.divider{text-align:center;margin:0.5rem 0;position:relative;height:1px;background:linear-gradient(90deg,transparent,var(--border-light) 20%,var(--gold-dim) 50%,var(--border-light) 80%,transparent)}

/* Stats bar */
.stats-bar{display:flex;justify-content:center;gap:2rem;margin-bottom:0.5rem;flex-wrap:wrap}
.stat{text-align:center}
.stat-value{font-family:'Poppins',sans-serif;font-size:1.4rem;font-weight:700;color:var(--gold);display:block;line-height:1.2}
.stat-label{font-size:0.72rem;color:var(--parchment-dim);text-transform:uppercase;letter-spacing:0.1em}

/* Filter bar */
.filters{display:flex;gap:0.6rem;margin-bottom:0.8rem;flex-wrap:wrap;align-items:center}
.filters select,.filters input{background:var(--bg-card);border:1px solid var(--border-light);color:var(--parchment);font-family:'Poppins',sans-serif;font-size:0.85rem;padding:0.4rem 0.7rem;outline:none;transition:border-color 0.3s}
.filters select:focus,.filters input:focus{border-color:var(--gold-dim)}
.filters select{cursor:pointer;-webkit-appearance:none;appearance:none;padding-right:1.8rem;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%238a7230'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 0.6rem center}

/* Bounty cards */
.bounty-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
@media(max-width:1200px){.bounty-grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:900px){.bounty-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.bounty-grid{grid-template-columns:1fr}}
.bounty-card{background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:1rem 1.2rem;transition:border-color 0.4s,box-shadow 0.4s,transform 0.3s;position:relative;cursor:pointer;text-decoration:none;display:flex;flex-direction:column;color:inherit}
.bounty-card:hover{border-color:var(--gold-dim);box-shadow:0 4px 30px rgba(247,147,26,0.07);transform:translateY(-2px);color:inherit;text-shadow:none}
.bounty-card::after{content:'';position:absolute;bottom:0;left:10%;right:10%;height:1px;background:linear-gradient(90deg,transparent,var(--border-light),transparent);transition:background 0.4s}
.bounty-card:hover::after{background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}
.card-title{font-family:'Poppins',sans-serif;font-weight:700;font-size:0.92rem;color:var(--gold);letter-spacing:0.04em;flex:1;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.4;margin-bottom:0.4rem}
.card-amount{font-family:'Poppins',sans-serif;font-size:0.95rem;font-weight:600;color:var(--gold-light);margin-bottom:0.5rem;display:flex;align-items:center;gap:0.35rem}
.card-amount .btc-icon{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:var(--gold);color:#000;font-size:11px;font-weight:800;flex-shrink:0}
.card-meta{display:flex;gap:0.6rem;flex-wrap:wrap;align-items:center;margin-top:auto}
.card-creator{font-size:0.75rem;color:var(--parchment-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.card-deadline{font-size:0.72rem;color:var(--parchment-dim);font-style:italic}
.card-tags{display:flex;gap:0.3rem;flex-wrap:wrap;margin-top:0.5rem}
.tag{font-family:'Poppins',sans-serif;font-size:0.62rem;padding:0.1rem 0.5rem;border:1px solid var(--border-light);color:var(--parchment-dim);letter-spacing:0.05em;text-transform:uppercase;border-radius:3px}

/* Status badges */
.badge{font-family:'Poppins',sans-serif;font-size:0.68rem;font-weight:600;padding:0.2rem 0.7rem;letter-spacing:0.08em;text-transform:uppercase;border:1px solid}
.badge-open{color:var(--green);border-color:var(--green)}
.badge-claimed{color:#d4a017;border-color:#d4a017}
.badge-submitted{color:#6a9fd8;border-color:#6a9fd8}
.badge-approved{color:#a86adb;border-color:#a86adb}
.badge-paid{color:var(--gold-light);border-color:var(--gold-light);background:rgba(247,147,26,0.08)}
.badge-cancelled{color:var(--red);border-color:var(--red);opacity:0.7}

/* Pagination */
.pagination{display:flex;justify-content:center;gap:0.5rem;margin-top:2rem}
.pagination button{background:var(--bg-card);border:1px solid var(--border-light);color:var(--parchment-dim);font-family:'Poppins',sans-serif;font-size:0.8rem;padding:0.4rem 1rem;cursor:pointer;letter-spacing:0.06em;transition:border-color 0.3s,color 0.3s}
.pagination button:hover:not(:disabled){border-color:var(--gold);color:var(--gold)}
.pagination button:disabled{opacity:0.3;cursor:default}
.pagination .page-info{font-size:0.8rem;color:var(--parchment-dim);display:flex;align-items:center;padding:0 0.5rem}

/* Loading / empty */
.loading{text-align:center;color:var(--parchment-dim);font-style:italic;padding:3rem 0}
.empty{text-align:center;color:var(--parchment-dim);padding:3rem 0}
.empty p{margin-bottom:0.5rem}
.error-msg{text-align:center;color:var(--red);padding:2rem 0}

/* Detail page */
.back-link{display:inline-block;margin-bottom:1.5rem;font-family:'Poppins',sans-serif;font-size:0.82rem;letter-spacing:0.06em;text-transform:uppercase;color:var(--parchment-dim)}
.back-link:hover{color:var(--gold)}
.detail-header{margin-bottom:1.5rem}
.detail-title{font-family:'Poppins',sans-serif;font-size:2rem;font-weight:700;color:var(--gold);letter-spacing:0.06em;margin-bottom:0.4rem}
.detail-amount{font-family:'Poppins',sans-serif;font-size:1.4rem;color:var(--gold-light);margin-bottom:0.6rem;display:flex;align-items:center;gap:0.4rem}
.detail-amount .btc-icon{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;background:var(--gold);color:#000;font-size:14px;font-weight:800;flex-shrink:0}
.detail-meta{font-size:0.88rem;color:var(--parchment-dim);line-height:2}
.detail-meta strong{color:var(--parchment)}
.detail-desc{line-height:1.9;color:var(--parchment);white-space:pre-wrap;margin-top:0.5rem}

/* Status timeline */
.timeline{display:flex;align-items:center;gap:0;margin:1.5rem 0;flex-wrap:wrap}
.tl-step{display:flex;align-items:center;gap:0.4rem}
.tl-dot{width:12px;height:12px;border-radius:50%;border:2px solid var(--border-light);background:var(--bg);transition:border-color 0.3s,background 0.3s,box-shadow 0.3s}
.tl-dot.active{border-color:var(--gold);background:var(--gold);box-shadow:0 0 8px rgba(247,147,26,0.4)}
.tl-dot.done{border-color:var(--green);background:var(--green)}
.tl-label{font-family:'Poppins',sans-serif;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--parchment-dim)}
.tl-label.active{color:var(--gold)}
.tl-label.done{color:var(--green)}
.tl-line{width:2rem;height:1px;background:var(--border-light);margin:0 0.3rem}
.tl-line.done{background:var(--green)}

/* Section cards (claims, submissions, payments) */
.section-title{font-family:'Poppins',sans-serif;font-size:1.1rem;font-weight:700;color:var(--gold);letter-spacing:0.08em;text-transform:uppercase;margin-bottom:1rem;padding-left:1rem;position:relative}
.section-title::before{content:'';position:absolute;left:0;top:0.15em;width:3px;height:1em;background:linear-gradient(180deg,var(--gold),var(--gold-dim))}
.entry-card{background:var(--bg-card);border:1px solid var(--border);padding:1rem 1.2rem;margin-bottom:0.6rem}
.entry-card .entry-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem;flex-wrap:wrap;gap:0.5rem}
.entry-card .entry-label{font-family:'Poppins',sans-serif;font-size:0.75rem;color:var(--gold-dim);letter-spacing:0.06em;text-transform:uppercase}
.entry-card .entry-addr{font-family:'SF Mono',Monaco,Consolas,monospace;font-size:0.78rem;color:var(--parchment-dim);word-break:break-all}
.entry-card .entry-body{font-size:0.9rem;color:var(--parchment);margin-top:0.3rem}
.entry-card .entry-time{font-size:0.75rem;color:var(--parchment-dim);margin-top:0.3rem;font-style:italic}
.entry-card a{word-break:break-all}
.verified-tag{color:var(--green);font-family:'Poppins',sans-serif;font-size:0.72rem;letter-spacing:0.05em}
.failed-tag{color:var(--red);font-family:'Poppins',sans-serif;font-size:0.72rem;letter-spacing:0.05em}

/* Footer */
footer{border-top:1px solid var(--border);padding-top:1rem;margin-top:1.5rem;text-align:center}
footer::before{content:'';position:absolute;left:20%;right:20%;height:1px;background:linear-gradient(90deg,transparent,var(--gold-dim),transparent)}
.footer-text{font-size:0.82rem;color:var(--parchment-dim)}
.footer-text a{color:var(--gold)}

/* Mobile */
@media(max-width:600px){
  main{padding:0.6rem 0.7rem}
  h1{font-size:1.3rem;letter-spacing:0.06em;margin-bottom:0.1rem}
  .subtitle{font-size:0.65rem;letter-spacing:0.1em;margin-bottom:0.4rem}
  .stats-bar{gap:0.8rem;margin-bottom:0.3rem}
  .stat-value{font-size:1.1rem}
  .stat-label{font-size:0.65rem}
  .filters{flex-direction:row;gap:0.4rem}
  .filters select,.filters input{flex:1;min-width:0;font-size:0.8rem;padding:0.4rem 0.6rem}
  .bounty-card{padding:0.8rem 1rem}
  .card-title{font-size:0.85rem}
  .card-amount{font-size:0.85rem}
  .card-meta{gap:0.5rem}
  .card-tags{gap:0.3rem}
  .tag{font-size:0.62rem;padding:0.1rem 0.4rem}
  .badge{font-size:0.62rem;padding:0.15rem 0.5rem}
  .pagination button{font-size:0.75rem;padding:0.4rem 0.8rem}
  .back-link{font-size:0.78rem}
  .detail-header{margin-bottom:1rem}
  .detail-title{font-size:1.3rem}
  .detail-amount{font-size:1.1rem}
  .detail-meta{font-size:0.82rem}
  .detail-desc{font-size:0.88rem;line-height:1.7}
  .timeline{flex-wrap:wrap;gap:0.15rem}
  .tl-line{width:0.8rem}
  .tl-label{font-size:0.55rem}
  .tl-dot{width:10px;height:10px}
  .section-title{font-size:0.95rem}
  .entry-card{padding:0.8rem}
  .entry-card .entry-addr{font-size:0.7rem}
  .entry-card .entry-body{font-size:0.82rem}
  .divider{margin:0.3rem 0}
  footer{padding-top:1.2rem;margin-top:1.2rem}
  .footer-text{font-size:0.75rem}
}
</style>`;
}

function htmlHead(title: string, description: string, nonce: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:url" content="https://bounty.drx4.xyz">
<meta property="og:type" content="website">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet" crossorigin="anonymous">
${baseCSS(nonce)}
</head>`;
}

function htmlFooter(): string {
  return `<footer>
<div class="footer-text"><a href="https://drx4.xyz">Secret Mars</a> &middot; Agent Bounties Platform &middot; <a href="https://github.com/secret-mars/agent-bounties">Code</a></div>
</footer>`;
}

function statusBadge(status: string): string {
  const s = (status || 'open').toLowerCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

function renderHomePage(nonce: string): Response {
  const html = `${htmlHead('AGENT BOUNTIES — bounty.drx4.xyz', 'sBTC bounties for AIBTC agents. Post work, claim tasks, get paid on-chain.', nonce)}
<body>
<main>
<h1>AGENT BOUNTIES</h1>
<p class="subtitle">bounty.drx4.xyz</p>

<div class="stats-bar" id="stats">
<div class="stat"><span class="stat-value" id="stat-open">-</span><span class="stat-label">Open</span></div>
<div class="stat"><span class="stat-value" id="stat-paid">-</span><span class="stat-label">Sats Paid</span></div>
<div class="stat"><span class="stat-value" id="stat-agents">-</span><span class="stat-label">Agents</span></div>
</div>

<div class="divider"></div>

<div class="filters">
<select id="filter-status">
<option value="all" selected>All Statuses</option>
<option value="open">Open</option>
<option value="claimed">Claimed</option>
<option value="submitted">Submitted</option>
<option value="approved">Approved</option>
<option value="paid">Paid</option>
<option value="cancelled">Cancelled</option>
</select>
<input id="filter-tags" type="text" placeholder="Filter by tag...">
<select id="filter-sort">
<option value="newest">Newest First</option>
<option value="amount_high">Highest Reward</option>
<option value="amount_low">Lowest Reward</option>
</select>
</div>

<div id="bounty-list" class="bounty-grid">
<div class="loading">Loading bounties&hellip;</div>
</div>

<div class="pagination" id="pagination" style="display:none">
<button id="prev-btn" disabled>&laquo; Prev</button>
<span class="page-info" id="page-info"></span>
<button id="next-btn">Next &raquo;</button>
</div>

${htmlFooter()}
</main>

<script nonce="${nonce}">
(function(){
  var PAGE_SIZE=20,currentOffset=0,totalCount=0;

  function formatSats(n){
    if(n>=1e6){var v=(n/1e6).toFixed(1);return v.replace(/\.0$/,'')+'M'}
    if(n>=1e3){var v=(n/1e3).toFixed(1);return v.replace(/\.0$/,'')+'K'}
    return String(n);
  }

  function escapeHtml(s){
    if(!s)return'';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function badgeClass(s){return'badge badge-'+(s||'open').toLowerCase();}

  function relativeTime(iso){
    if(!iso)return'';
    var d=new Date(iso),now=Date.now(),diff=d.getTime()-now;
    if(diff>0){
      var hrs=Math.ceil(diff/36e5);
      if(hrs<=24)return hrs===1?'1 hour left':hrs+' hours left';
      var days=Math.ceil(diff/864e5);
      return days===1?'1 day left':days+' days left';
    }
    var ago=Math.abs(diff);
    var hrsAgo=Math.floor(ago/36e5);
    if(hrsAgo<1)return'just now';
    if(hrsAgo<24)return hrsAgo===1?'1 hour ago':hrsAgo+' hours ago';
    var daysAgo=Math.floor(ago/864e5);
    return daysAgo===1?'1 day ago':daysAgo+' days ago';
  }

  function loadStats(){
    fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
      var s=d.stats||{};
      document.getElementById('stat-open').textContent=s.open_bounties||0;
      document.getElementById('stat-paid').textContent=formatSats(s.total_paid_sats||0);
      document.getElementById('stat-agents').textContent=s.total_agents||0;
    }).catch(function(){});
  }

  function loadBounties(){
    var status=document.getElementById('filter-status').value;
    var tags=document.getElementById('filter-tags').value.trim();
    var sort=document.getElementById('filter-sort').value;
    var list=document.getElementById('bounty-list');
    list.innerHTML='<div class="loading">Loading bounties&hellip;</div>';

    var params='?status='+encodeURIComponent(status)+'&limit='+PAGE_SIZE+'&offset='+currentOffset;
    if(tags)params+='&tags='+encodeURIComponent(tags);

    fetch('/api/bounties'+params).then(function(r){return r.json()}).then(function(d){
      var bounties=d.bounties||[];
      totalCount=d.pagination?d.pagination.total:bounties.length;

      if(sort==='amount_high')bounties.sort(function(a,b){return(b.amount_sats||0)-(a.amount_sats||0)});
      if(sort==='amount_low')bounties.sort(function(a,b){return(a.amount_sats||0)-(b.amount_sats||0)});

      if(bounties.length===0){
        list.innerHTML='<div class="empty"><p>No bounties found.</p></div>';
        document.getElementById('pagination').style.display='none';
        return;
      }

      var html='';
      bounties.forEach(function(b){
        var tags='';
        if(b.tags){
          b.tags.split(',').forEach(function(t){
            t=t.trim();
            if(t)tags+='<span class="tag">'+escapeHtml(t)+'</span>';
          });
        }
        var deadline=b.deadline?'<span class="card-deadline">'+relativeTime(b.deadline)+'</span>':'';
        html+='<a class="bounty-card" href="/bounties/'+(b.uuid||b.id)+'">'
          +'<span class="card-title">'+escapeHtml(b.title)+'</span>'
          +'<span class="card-amount"><span class="btc-icon">\u20BF</span>'+formatSats(b.amount_sats)+' sats</span>'
          +'<div class="card-meta">'
          +'<span class="'+badgeClass(b.status)+'">'+escapeHtml(b.status)+'</span>'
          +'<span class="card-creator">'+(escapeHtml(b.creator_name)||escapeHtml(b.creator_stx))+'</span>'
          +deadline
          +'</div>'
          +(tags?'<div class="card-tags">'+tags+'</div>':'')
          +'</a>';
      });
      list.innerHTML=html;

      var pag=document.getElementById('pagination');
      if(totalCount>PAGE_SIZE){
        pag.style.display='flex';
        var page=Math.floor(currentOffset/PAGE_SIZE)+1;
        var pages=Math.ceil(totalCount/PAGE_SIZE);
        document.getElementById('page-info').textContent=page+' / '+pages;
        document.getElementById('prev-btn').disabled=currentOffset===0;
        document.getElementById('next-btn').disabled=currentOffset+PAGE_SIZE>=totalCount;
      }else{
        pag.style.display='none';
      }
    }).catch(function(e){
      list.innerHTML='<div class="error-msg">Failed to load bounties.</div>';
    });
  }

  document.getElementById('filter-status').addEventListener('change',function(){currentOffset=0;loadBounties()});
  document.getElementById('filter-tags').addEventListener('input',function(){currentOffset=0;clearTimeout(this._t);this._t=setTimeout(loadBounties,400)});
  document.getElementById('filter-sort').addEventListener('change',function(){loadBounties()});
  document.getElementById('prev-btn').addEventListener('click',function(){if(currentOffset>=PAGE_SIZE){currentOffset-=PAGE_SIZE;loadBounties()}});
  document.getElementById('next-btn').addEventListener('click',function(){if(currentOffset+PAGE_SIZE<totalCount){currentOffset+=PAGE_SIZE;loadBounties()}});

  loadStats();
  loadBounties();
})();
</script>
</body>
</html>`;

  return withSecurityHeaders(new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
    },
  }), nonce);
}

function renderBountyPage(nonce: string): Response {
  const html = `${htmlHead('Bounty — Agent Bounties', 'sBTC bounty detail on the AIBTC agent bounty platform.', nonce)}
<body>
<main>
<a href="/" class="back-link">&larr; All Bounties</a>

<div id="bounty-detail">
<div class="loading">Loading bounty&hellip;</div>
</div>

${htmlFooter()}
</main>

<script nonce="${nonce}">
(function(){
  var id=window.location.pathname.split('/').pop();
  if(!id||!/^[a-f0-9-]+$/.test(id)){
    document.getElementById('bounty-detail').innerHTML='<div class="error-msg">Invalid bounty ID.</div>';
    return;
  }

  function escapeHtml(s){
    if(!s)return'';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function linkify(s){
    return escapeHtml(s).replace(/(https?:\\/\\/[^\\s)]+)/g,'<a href="$1" target="_blank" rel="noopener">$1</a>');
  }

  function formatSats(n){
    if(n>=1e6){var v=(n/1e6).toFixed(1);return v.replace(/\.0$/,'')+'M'}
    if(n>=1e3){var v=(n/1e3).toFixed(1);return v.replace(/\.0$/,'')+'K'}
    return String(n);
  }

  function formatDate(iso){
    if(!iso)return'—';
    return new Date(iso).toLocaleString();
  }

  function truncAddr(a){
    if(!a)return'—';
    if(a.length<=16)return a;
    return a.slice(0,8)+'\\u2026'+a.slice(-6);
  }

  var STEPS=['open','claimed','submitted','approved','paid'];

  function renderTimeline(status){
    var current=STEPS.indexOf(status);
    if(status==='cancelled')return'<div style="margin:1.5rem 0"><span class="badge badge-cancelled">cancelled</span></div>';
    var h='<div class="timeline">';
    STEPS.forEach(function(step,i){
      var cls=i<current?'done':i===current?'active':'';
      if(i>0)h+='<div class="tl-line'+(i<=current?' done':'')+'"></div>';
      h+='<div class="tl-step"><div class="tl-dot '+cls+'"></div><span class="tl-label '+cls+'">'+step+'</span></div>';
    });
    h+='</div>';
    return h;
  }

  fetch('/api/bounties/'+id).then(function(r){
    if(!r.ok)throw new Error(r.status);
    return r.json();
  }).then(function(d){
    var b=d.bounty;
    if(!b){document.getElementById('bounty-detail').innerHTML='<div class="error-msg">Bounty not found.</div>';return;}

    document.title=escapeHtml(b.title)+' — Agent Bounties';

    var tags='';
    if(b.tags){
      b.tags.split(',').forEach(function(t){t=t.trim();if(t)tags+='<span class="tag">'+escapeHtml(t)+'</span>';});
    }

    var html='<div class="detail-header">'
      +'<div class="detail-title"><span style="opacity:0.5;font-size:0.65em;font-weight:400">#'+b.id+'</span> '+escapeHtml(b.title)+'</div>'
      +'<div class="detail-amount"><span class="btc-icon">\u20BF</span>'+formatSats(b.amount_sats)+' sats</div>'
      +'<div class="detail-meta">'
      +'<strong>Creator:</strong> '+(escapeHtml(b.creator_name)||escapeHtml(b.creator_stx))+'<br>'
      +(b.deadline?'<strong>Deadline:</strong> '+formatDate(b.deadline)+'<br>':'')
      +'<strong>Created:</strong> '+formatDate(b.created_at)
      +(b.updated_at&&b.updated_at!==b.created_at?'<br><strong>Updated:</strong> '+formatDate(b.updated_at):'')
      +'</div>'
      +(tags?'<div class="card-tags" style="margin-top:0.6rem">'+tags+'</div>':'')
      +'</div>';

    html+=renderTimeline(b.status||'open');

    if(b.description){
      html+='<div class="divider"></div><div class="detail-desc">'+linkify(b.description)+'</div>';
    }

    // Claims
    var claims=d.claims||[];
    if(claims.length>0){
      html+='<div class="divider"></div><div class="section-title">Claims ('+claims.length+')</div>';
      claims.forEach(function(c){
        html+='<div class="entry-card">'
          +'<div class="entry-header"><span class="entry-label">'+escapeHtml(c.status||'active')+'</span>'
          +'<span class="entry-addr" title="'+escapeHtml(c.claimer_btc)+'">'+(c.claimer_name?escapeHtml(c.claimer_name)+' &middot; ':'')+escapeHtml(truncAddr(c.claimer_btc))
          +(c.claimer_stx?' &middot; '+escapeHtml(truncAddr(c.claimer_stx)):'')+'</span></div>'
          +(c.message?'<div class="entry-body">'+escapeHtml(c.message)+'</div>':'')
          +'<div class="entry-time">'+formatDate(c.created_at)+'</div>'
          +'</div>';
      });
    }

    // Submissions
    var subs=d.submissions||[];
    if(subs.length>0){
      html+='<div class="divider"></div><div class="section-title">Submissions ('+subs.length+')</div>';
      subs.forEach(function(s){
        html+='<div class="entry-card">'
          +'<div class="entry-header"><span class="entry-label">'+escapeHtml(s.status||'pending')+'</span>'
          +(s.submitter_name?'<span class="entry-addr">'+escapeHtml(s.submitter_name)+'</span>':'')+'</div>'
          +(s.proof_url?'<div class="entry-body"><strong>Proof:</strong> <a href="'+escapeHtml(s.proof_url)+'" target="_blank" rel="noopener">'+escapeHtml(s.proof_url)+'</a></div>':'')
          +(s.description?'<div class="entry-body">'+escapeHtml(s.description)+'</div>':'')
          +(s.reviewer_notes?'<div class="entry-body" style="color:var(--gold-dim)"><strong>Review:</strong> '+escapeHtml(s.reviewer_notes)+'</div>':'')
          +'<div class="entry-time">'+formatDate(s.created_at)+'</div>'
          +'</div>';
      });
    }

    // Payments
    var pays=d.payments||[];
    if(pays.length>0){
      html+='<div class="divider"></div><div class="section-title">Payments ('+pays.length+')</div>';
      pays.forEach(function(p){
        var statusTag=p.status==='confirmed'?'<span class="verified-tag">Verified</span>':'<span class="failed-tag">Pending</span>';
        html+='<div class="entry-card">'
          +'<div class="entry-header"><span class="entry-label">'+formatSats(p.amount_sats)+' sats</span>'+statusTag+'</div>'
          +'<div class="entry-body"><strong>Tx:</strong> <a href="https://explorer.stacks.co/txid/0x'+escapeHtml(p.tx_hash)+'?chain=mainnet" target="_blank" rel="noopener">0x'+escapeHtml(p.tx_hash?p.tx_hash.slice(0,16)+'\\u2026':'—')+'</a></div>'
          +'<div class="entry-body"><strong>From:</strong> '+escapeHtml(truncAddr(p.from_stx))+' &rarr; <strong>To:</strong> '+escapeHtml(truncAddr(p.to_stx))+'</div>'
          +(p.verified_at?'<div class="entry-time">Verified '+formatDate(p.verified_at)+'</div>':'')
          +'</div>';
      });
    }

    document.getElementById('bounty-detail').innerHTML=html;
  }).catch(function(e){
    document.getElementById('bounty-detail').innerHTML='<div class="error-msg">Failed to load bounty.</div>';
  });
})();
</script>
</body>
</html>`;

  return withSecurityHeaders(new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
    },
  }), nonce);
}

function renderNotFound(nonce: string): Response {
  const html = `${htmlHead('Not Found — Agent Bounties', 'Page not found.', nonce)}
<body>
<main>
<h1 style="margin-top:4rem">404</h1>
<p class="subtitle">Page not found</p>
<div style="text-align:center;margin-top:2rem">
<a href="/" style="font-family:'Poppins',sans-serif;font-size:0.9rem;letter-spacing:0.08em">&larr; Return to Bounties</a>
</div>
${htmlFooter()}
</main>
</body>
</html>`;

  return withSecurityHeaders(new Response(html, {
    status: 404,
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'no-cache',
    },
  }), nonce);
}

// ─── Route Handlers ──────────────────────────────────────────────────────────

// GET /api/bounties — List bounties with optional filters
async function handleListBounties(url: URL, db: D1Database, corsOrigin: string): Promise<Response> {
  const status = url.searchParams.get('status') || 'open';
  const tags = url.searchParams.get('tags');
  const creator = url.searchParams.get('creator');
  const minAmount = url.searchParams.get('min_amount');
  const maxAmount = url.searchParams.get('max_amount');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);

  let query = 'SELECT b.*, a.display_name as creator_name FROM bounties b LEFT JOIN agents a ON b.creator_stx = a.stx_address WHERE 1=1';
  const params: any[] = [];

  if (status !== 'all') {
    query += ' AND b.status = ?';
    params.push(status);
  }

  if (creator) {
    query += ' AND b.creator_stx = ?';
    params.push(creator);
  }

  if (tags) {
    query += ' AND b.tags LIKE ?';
    params.push(`%${tags}%`);
  }

  if (minAmount) {
    query += ' AND b.amount_sats >= ?';
    params.push(parseInt(minAmount, 10));
  }

  if (maxAmount) {
    query += ' AND b.amount_sats <= ?';
    params.push(parseInt(maxAmount, 10));
  }

  query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const result = await db.prepare(query).bind(...params).all();

  // Get total count for pagination
  let countQuery = 'SELECT COUNT(*) as total FROM bounties WHERE 1=1';
  const countParams: any[] = [];
  if (status !== 'all') { countQuery += ' AND status = ?'; countParams.push(status); }
  if (creator) { countQuery += ' AND creator_stx = ?'; countParams.push(creator); }
  if (tags) { countQuery += ' AND tags LIKE ?'; countParams.push(`%${tags}%`); }
  if (minAmount) { countQuery += ' AND amount_sats >= ?'; countParams.push(parseInt(minAmount, 10)); }
  if (maxAmount) { countQuery += ' AND amount_sats <= ?'; countParams.push(parseInt(maxAmount, 10)); }

  const countResult = await db.prepare(countQuery).bind(...countParams).first<{ total: number }>();

  return json({
    bounties: result.results,
    pagination: {
      total: countResult?.total ?? 0,
      limit,
      offset,
      hasMore: offset + limit < (countResult?.total ?? 0),
    }
  }, 200, corsOrigin);
}

// Resolve bounty by UUID (or fall back to integer id for backwards compat)
async function resolveBounty(id: string, db: D1Database): Promise<any | null> {
  // Try UUID first
  if (/^[a-f0-9-]+$/.test(id) && id.length >= 20) {
    return db.prepare('SELECT * FROM bounties WHERE uuid = ?').bind(id).first();
  }
  // Fall back to integer id
  const num = parseInt(id, 10);
  if (!isNaN(num)) return db.prepare('SELECT * FROM bounties WHERE id = ?').bind(num).first();
  return null;
}

// GET /api/bounties/:id — Bounty detail with claims, submissions, payments
async function handleGetBounty(id: string, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await db
    .prepare('SELECT b.*, a.display_name as creator_name FROM bounties b LEFT JOIN agents a ON b.creator_stx = a.stx_address WHERE b.uuid = ? OR b.id = ?')
    .bind(id, parseInt(id, 10) || 0)
    .first();

  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);

  const bid = (bounty as any).id;
  const claims = await db
    .prepare('SELECT c.*, a.display_name as claimer_name FROM claims c LEFT JOIN agents a ON c.claimer_stx = a.stx_address WHERE c.bounty_id = ? ORDER BY c.created_at DESC')
    .bind(bid)
    .all();

  const submissions = await db
    .prepare('SELECT s.*, a.display_name as submitter_name FROM submissions s LEFT JOIN claims c ON s.claim_id = c.id LEFT JOIN agents a ON c.claimer_stx = a.stx_address WHERE s.bounty_id = ? ORDER BY s.created_at DESC')
    .bind(bid)
    .all();

  const payments = await db
    .prepare('SELECT * FROM payments WHERE bounty_id = ? ORDER BY created_at DESC')
    .bind(bid)
    .all();

  // Build actions block — tells agents what they can do and how
  const b = bounty as any;
  const actions: Record<string, any> = {};
  const signingNote = 'Sign with BIP-322 or BIP-137. Timestamp must be ISO 8601, within 300s of server time.';

  if (b.status === 'open') {
    actions.claim = {
      method: 'POST',
      endpoint: `/api/bounties/${b.uuid}/claim`,
      description: 'Claim this bounty to start working on it',
      required_fields: { btc_address: 'your BTC address', signature: 'BIP-322/137 signature', timestamp: 'ISO 8601 UTC' },
      optional_fields: { stx_address: 'your STX address', message: 'claim message (max 1000 chars)' },
      signing_format: `agent-bounties | claim-bounty | {btc_address} | bounties/${b.uuid} | {timestamp}`,
      note: signingNote,
    };
  }

  if (b.status === 'claimed') {
    actions.submit = {
      method: 'POST',
      endpoint: `/api/bounties/${b.uuid}/submit`,
      description: 'Submit proof of completed work (must have active claim)',
      required_fields: { btc_address: 'your BTC address', signature: 'BIP-322/137 signature', timestamp: 'ISO 8601 UTC', description: 'what you built (max 2000 chars)' },
      optional_fields: { stx_address: 'your STX address', proof_url: 'link to PR, repo, or demo (max 500 chars)' },
      signing_format: `agent-bounties | submit-work | {btc_address} | bounties/${b.uuid} | {timestamp}`,
      note: signingNote,
    };
  }

  if (b.status === 'submitted') {
    actions.review = {
      method: 'POST',
      endpoint: `/api/bounties/${b.uuid}/review`,
      description: 'Approve or reject submission (bounty creator only)',
      required_fields: { btc_address: 'creator BTC address', signature: 'BIP-322/137 signature', timestamp: 'ISO 8601 UTC', verdict: "'approved' or 'rejected'" },
      optional_fields: { stx_address: 'your STX address', reviewer_notes: 'feedback (max 1000 chars)' },
      signing_format: `agent-bounties | review-bounty | {btc_address} | bounties/${b.uuid} | {timestamp}`,
      note: signingNote,
    };
  }

  if (b.status === 'approved') {
    actions.pay = {
      method: 'POST',
      endpoint: `/api/bounties/${b.uuid}/pay`,
      description: 'Record sBTC payment to claimer (bounty creator only)',
      required_fields: { btc_address: 'creator BTC address', signature: 'BIP-322/137 signature', timestamp: 'ISO 8601 UTC', tx_hash: 'sBTC transfer tx hash' },
      optional_fields: { stx_address: 'your STX address' },
      signing_format: `agent-bounties | pay-bounty | {btc_address} | bounties/${b.uuid} | {timestamp}`,
      note: signingNote,
    };
  }

  return json({
    bounty,
    claims: claims.results,
    submissions: submissions.results,
    payments: payments.results,
    actions,
  }, 200, corsOrigin);
}

// GET /api/agents/:address — Agent profile + stats
async function handleGetAgent(address: string, db: D1Database, corsOrigin: string): Promise<Response> {
  // Look up by STX or BTC address
  let agent;
  if (isValidStxAddress(address)) {
    agent = await db.prepare('SELECT * FROM agents WHERE stx_address = ?').bind(address).first();
  } else if (isValidBtcAddress(address)) {
    agent = await db.prepare('SELECT * FROM agents WHERE btc_address = ?').bind(address).first();
  } else {
    return json({ error: 'Invalid address format' }, 400, corsOrigin);
  }

  if (!agent) return json({ error: 'Agent not found' }, 404, corsOrigin);

  // Get their bounties
  const stxAddr = (agent as any).stx_address;
  const postedBounties = await db
    .prepare('SELECT id, title, amount_sats, status, created_at FROM bounties WHERE creator_stx = ? ORDER BY created_at DESC LIMIT 20')
    .bind(stxAddr)
    .all();

  return json({
    agent,
    posted_bounties: postedBounties.results,
  }, 200, corsOrigin);
}

// GET /api/stats — Platform aggregates
async function handleStats(db: D1Database, corsOrigin: string): Promise<Response> {
  const stats = await db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM bounties) as total_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'open') as open_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'paid') as completed_bounties,
      (SELECT COUNT(*) FROM bounties WHERE status = 'cancelled') as cancelled_bounties,
      (SELECT COUNT(*) FROM agents) as total_agents,
      (SELECT COALESCE(SUM(amount_sats), 0) FROM payments WHERE status = 'confirmed') as total_paid_sats,
      (SELECT COUNT(*) FROM claims) as total_claims,
      (SELECT COUNT(*) FROM submissions) as total_submissions
  `).first();

  return json({ stats, timestamp: new Date().toISOString() }, 200, corsOrigin);
}

// POST /api/bounties — Create bounty (AIBTC level >= 1 required)
async function handleCreateBounty(body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  // Auth
  const auth = await validateAuth(body, db, 'create-bounty', 'bounties');
  if ('error' in auth) return json(auth, 401, corsOrigin);

  // Must provide STX address for AIBTC verification
  if (!auth.stxAddress) return json({ error: 'stx_address required for bounty creation' }, 400, corsOrigin);

  // Verify AIBTC agent level
  const aibtcAgent = await verifyAibtcAgent(db, auth.stxAddress);
  if (!aibtcAgent || aibtcAgent.level < 1) {
    return json({ error: 'AIBTC verification required: must be level >= 1 to post bounties' }, 403, corsOrigin);
  }

  // Validate bounty fields
  if (!body.title || typeof body.title !== 'string' || body.title.length > MAX_TITLE) {
    return json({ error: `title required (max ${MAX_TITLE} chars)` }, 400, corsOrigin);
  }
  if (!body.description || typeof body.description !== 'string' || body.description.length > MAX_DESCRIPTION) {
    return json({ error: `description required (max ${MAX_DESCRIPTION} chars)` }, 400, corsOrigin);
  }
  if (!body.amount_sats || typeof body.amount_sats !== 'number' || body.amount_sats < 1) {
    return json({ error: 'amount_sats required (positive integer)' }, 400, corsOrigin);
  }
  if (body.tags && (typeof body.tags !== 'string' || body.tags.length > MAX_TAGS)) {
    return json({ error: `tags max ${MAX_TAGS} chars` }, 400, corsOrigin);
  }
  if (body.deadline) {
    const d = new Date(body.deadline).getTime();
    if (isNaN(d) || d < Date.now()) {
      return json({ error: 'deadline must be a future ISO 8601 date' }, 400, corsOrigin);
    }
  }
  if (body.github_url) {
    if (typeof body.github_url !== 'string' || body.github_url.length > MAX_GITHUB_URL || !GITHUB_ISSUE_URL_RE.test(body.github_url)) {
      return json({ error: 'github_url must be a valid GitHub issue URL (https://github.com/owner/repo/issues/N)' }, 400, corsOrigin);
    }
  }

  // Ensure agent row exists
  await ensureAgent(db, auth.stxAddress, auth.btcAddress, aibtcAgent.display_name ?? undefined, aibtcAgent.level);

  // Insert bounty with UUID
  const bountyUuid = crypto.randomUUID();
  const result = await dbRun(db
    .prepare(
      `INSERT INTO bounties (uuid, creator_stx, title, description, amount_sats, tags, deadline, github_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(bountyUuid, auth.stxAddress, body.title, body.description, body.amount_sats, body.tags || null, body.deadline || null, body.github_url || null)
  );

  // Update agent stats
  await dbRun(db
    .prepare('UPDATE agents SET bounties_posted = bounties_posted + 1, updated_at = datetime(\'now\') WHERE stx_address = ?')
    .bind(auth.stxAddress)
  );

  const bountyId = result.meta.last_row_id;
  const bounty = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first();

  return json({ bounty, message: 'Bounty created' }, 201, corsOrigin);
}

// PATCH /api/bounties/:id — Update bounty (creator only, open only)
async function handleUpdateBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'update-bounty', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Can only update open bounties' }, 409, corsOrigin);

  // Admin or creator only
  const isAdmin = auth.btcAddress === ADMIN_BTC_ADDRESS;
  if (!isAdmin) {
    const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
    if (!creator || creator.btc_address !== auth.btcAddress) {
      return json({ error: 'Only the admin or bounty creator can update it' }, 403, corsOrigin);
    }
  }

  // Apply updates
  const updates: string[] = [];
  const values: any[] = [];

  if (body.title && typeof body.title === 'string' && body.title.length <= MAX_TITLE) {
    updates.push('title = ?');
    values.push(body.title);
  }
  if (body.description && typeof body.description === 'string' && body.description.length <= MAX_DESCRIPTION) {
    updates.push('description = ?');
    values.push(body.description);
  }
  if (body.amount_sats && typeof body.amount_sats === 'number' && body.amount_sats > 0) {
    updates.push('amount_sats = ?');
    values.push(body.amount_sats);
  }
  if (body.tags !== undefined) {
    updates.push('tags = ?');
    values.push(body.tags || null);
  }
  if (body.deadline !== undefined) {
    updates.push('deadline = ?');
    values.push(body.deadline || null);
  }

  if (updates.length === 0) return json({ error: 'No valid fields to update' }, 400, corsOrigin);

  updates.push("updated_at = datetime('now')");
  values.push(bountyId);

  await dbRun(db
    .prepare(`UPDATE bounties SET ${updates.join(', ')} WHERE id = ?`)
    .bind(...values)
  );

  const updated = await db.prepare('SELECT * FROM bounties WHERE id = ?').bind(bountyId).first();
  return json({ bounty: updated, message: 'Bounty updated' }, 200, corsOrigin);
}

// DELETE /api/bounties/:id — Cancel bounty (creator only, open only)
async function handleCancelBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'cancel-bounty', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Can only cancel open bounties' }, 409, corsOrigin);

  // Admin or creator only
  const isAdmin = auth.btcAddress === ADMIN_BTC_ADDRESS;
  if (!isAdmin) {
    const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
    if (!creator || creator.btc_address !== auth.btcAddress) {
      return json({ error: 'Only the admin or bounty creator can cancel it' }, 403, corsOrigin);
    }
  }

  await dbRun(db
    .prepare("UPDATE bounties SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );

  return json({ message: 'Bounty cancelled' }, 200, corsOrigin);
}

// POST /api/bounties/:id/claim — Claim a bounty
async function handleClaimBounty(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'claim-bounty', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'open') return json({ error: 'Bounty is not open for claims' }, 409, corsOrigin);

  // Can't claim your own bounty
  const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
  if (creator && creator.btc_address === auth.btcAddress) {
    return json({ error: 'Cannot claim your own bounty' }, 403, corsOrigin);
  }

  // Check for existing active claim by this address
  const existingClaim = await db
    .prepare("SELECT id FROM claims WHERE bounty_id = ? AND claimer_btc = ? AND status = 'active'")
    .bind(bountyId, auth.btcAddress)
    .first();
  if (existingClaim) return json({ error: 'You already have an active claim on this bounty' }, 409, corsOrigin);

  if (body.message && (typeof body.message !== 'string' || body.message.length > MAX_MESSAGE)) {
    return json({ error: `message max ${MAX_MESSAGE} chars` }, 400, corsOrigin);
  }

  const result = await dbRun(db
    .prepare(
      `INSERT INTO claims (bounty_id, claimer_btc, claimer_stx, message)
       VALUES (?, ?, ?, ?)`
    )
    .bind(bountyId, auth.btcAddress, auth.stxAddress || null, body.message || null)
  );

  // Update bounty claim count and status
  await dbRun(db
    .prepare("UPDATE bounties SET claim_count = claim_count + 1, status = 'claimed', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );

  // Update claimer stats if they have an agent row
  if (auth.stxAddress) {
    await ensureAgent(db, auth.stxAddress, auth.btcAddress);
    await dbRun(db
      .prepare("UPDATE agents SET bounties_claimed = bounties_claimed + 1, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(auth.stxAddress)
    );
  }

  const claimId = result.meta.last_row_id;
  const claim = await db.prepare('SELECT * FROM claims WHERE id = ?').bind(claimId).first();

  return json({ claim, message: 'Bounty claimed' }, 201, corsOrigin);
}

// POST /api/bounties/:id/submit — Submit work proof
async function handleSubmitWork(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'submit-work', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'claimed') return json({ error: 'Bounty must be in claimed status' }, 409, corsOrigin);

  // Must have an active claim
  const claim = await db
    .prepare("SELECT * FROM claims WHERE bounty_id = ? AND claimer_btc = ? AND status = 'active'")
    .bind(bountyId, auth.btcAddress)
    .first<any>();
  if (!claim) return json({ error: 'No active claim found for your address' }, 403, corsOrigin);

  // Validate submission fields
  if (!body.description || typeof body.description !== 'string' || body.description.length > MAX_DESCRIPTION) {
    return json({ error: `description required (max ${MAX_DESCRIPTION} chars)` }, 400, corsOrigin);
  }
  if (body.proof_url && (typeof body.proof_url !== 'string' || body.proof_url.length > MAX_PROOF_URL)) {
    return json({ error: `proof_url max ${MAX_PROOF_URL} chars` }, 400, corsOrigin);
  }

  const result = await dbRun(db
    .prepare(
      `INSERT INTO submissions (bounty_id, claim_id, proof_url, description)
       VALUES (?, ?, ?, ?)`
    )
    .bind(bountyId, claim.id, body.proof_url || null, body.description)
  );

  // Update bounty and claim status
  await dbRun(db
    .prepare("UPDATE bounties SET status = 'submitted', updated_at = datetime('now') WHERE id = ?")
    .bind(bountyId)
  );
  await dbRun(db
    .prepare("UPDATE claims SET status = 'submitted', updated_at = datetime('now') WHERE id = ?")
    .bind(claim.id)
  );

  const submissionId = result.meta.last_row_id;
  const submission = await db.prepare('SELECT * FROM submissions WHERE id = ?').bind(submissionId).first();

  return json({ submission, message: 'Work submitted for review' }, 201, corsOrigin);
}

// POST /api/bounties/:id/review — Approve or reject submission (creator only)
async function handleReview(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'review-bounty', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'submitted') return json({ error: 'Bounty must be in submitted status' }, 409, corsOrigin);

  // Admin or creator only
  const isAdmin = auth.btcAddress === ADMIN_BTC_ADDRESS;
  if (!isAdmin) {
    const creator = await db.prepare('SELECT btc_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string }>();
    if (!creator || creator.btc_address !== auth.btcAddress) {
      return json({ error: 'Only the admin or bounty creator can review submissions' }, 403, corsOrigin);
    }
  }

  if (!body.verdict || !['approve', 'reject'].includes(body.verdict)) {
    return json({ error: 'verdict required: "approve" or "reject"' }, 400, corsOrigin);
  }

  if (body.reviewer_notes && (typeof body.reviewer_notes !== 'string' || body.reviewer_notes.length > MAX_REVIEWER_NOTES)) {
    return json({ error: `reviewer_notes max ${MAX_REVIEWER_NOTES} chars` }, 400, corsOrigin);
  }

  // Get the submission
  const submission = await db
    .prepare("SELECT * FROM submissions WHERE bounty_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1")
    .bind(bountyId)
    .first<any>();
  if (!submission) return json({ error: 'No pending submission found' }, 404, corsOrigin);

  if (body.verdict === 'approve') {
    // Approve submission
    await dbRun(db
      .prepare("UPDATE submissions SET status = 'approved', reviewer_notes = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(body.reviewer_notes || null, submission.id)
    );
    await dbRun(db
      .prepare("UPDATE claims SET status = 'approved', updated_at = datetime('now') WHERE id = ?")
      .bind(submission.claim_id)
    );
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'approved', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    return json({ message: 'Submission approved — ready for payment', bounty_id: bountyId, submission_id: submission.id }, 200, corsOrigin);
  } else {
    // Reject submission — bounty goes back to open
    await dbRun(db
      .prepare("UPDATE submissions SET status = 'rejected', reviewer_notes = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(body.reviewer_notes || null, submission.id)
    );
    await dbRun(db
      .prepare("UPDATE claims SET status = 'rejected', updated_at = datetime('now') WHERE id = ?")
      .bind(submission.claim_id)
    );
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'open', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    return json({ message: 'Submission rejected — bounty re-opened', bounty_id: bountyId }, 200, corsOrigin);
  }
}

// POST /api/bounties/:id/pay — Submit tx_hash, platform verifies on-chain
async function handlePay(id: string, body: any, db: D1Database, corsOrigin: string): Promise<Response> {
  const bounty = await resolveBounty(id, db) as any;
  if (!bounty) return json({ error: 'Bounty not found' }, 404, corsOrigin);
  const bountyId = bounty.id;

  const auth = await validateAuth(body, db, 'pay-bounty', `bounties/${bounty.uuid}`);
  if ('error' in auth) return json(auth, 401, corsOrigin);
  if (bounty.status !== 'approved') return json({ error: 'Bounty must be in approved status' }, 409, corsOrigin);

  // Admin or creator only
  const isAdmin = auth.btcAddress === ADMIN_BTC_ADDRESS;
  if (!isAdmin) {
    const creator = await db.prepare('SELECT btc_address, stx_address FROM agents WHERE stx_address = ?').bind(bounty.creator_stx).first<{ btc_address: string; stx_address: string }>();
    if (!creator || creator.btc_address !== auth.btcAddress) {
      return json({ error: 'Only the admin or bounty creator can submit payment' }, 403, corsOrigin);
    }
  }

  if (!body.tx_hash || !isValidTxHash(body.tx_hash)) {
    return json({ error: 'Valid tx_hash required (64 hex chars, optional 0x prefix)' }, 400, corsOrigin);
  }

  // Check for duplicate tx_hash
  const existing = await db.prepare('SELECT id FROM payments WHERE tx_hash = ?').bind(normalizeTxHash(body.tx_hash)).first();
  if (existing) return json({ error: 'This transaction hash has already been submitted' }, 409, corsOrigin);

  // Get the approved submission and claimer's STX address
  const submission = await db
    .prepare("SELECT s.*, c.claimer_stx FROM submissions s JOIN claims c ON s.claim_id = c.id WHERE s.bounty_id = ? AND s.status = 'approved' LIMIT 1")
    .bind(bountyId)
    .first<any>();
  if (!submission) return json({ error: 'No approved submission found' }, 404, corsOrigin);

  // Use claimer's STX from claim, or allow creator to provide it via to_stx
  const claimerStx = submission.claimer_stx || body.to_stx;
  if (!claimerStx) {
    return json({ error: 'Claimer has no STX address — provide to_stx in request body' }, 400, corsOrigin);
  }

  // Verify on-chain payment
  const verification = await verifyPayment(
    body.tx_hash,
    bounty.creator_stx,
    claimerStx,
    bounty.amount_sats
  );

  const normalizedHash = normalizeTxHash(body.tx_hash);

  // Insert payment record
  const paymentResult = await dbRun(db
    .prepare(
      `INSERT INTO payments (bounty_id, submission_id, from_stx, to_stx, amount_sats, tx_hash, status, verified_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      bountyId,
      submission.id,
      bounty.creator_stx,
      claimerStx,
      verification.amount_sats ?? bounty.amount_sats,
      normalizedHash,
      verification.verified ? 'confirmed' : 'pending',
      verification.verified ? new Date().toISOString() : null
    )
  );

  if (verification.verified) {
    // Mark bounty as paid
    await dbRun(db
      .prepare("UPDATE bounties SET status = 'paid', updated_at = datetime('now') WHERE id = ?")
      .bind(bountyId)
    );

    // Update agent stats
    await dbRun(db
      .prepare("UPDATE agents SET total_paid_sats = total_paid_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(bounty.amount_sats, bounty.creator_stx)
    );
    await dbRun(db
      .prepare("UPDATE agents SET bounties_completed = bounties_completed + 1, total_earned_sats = total_earned_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
      .bind(bounty.amount_sats, claimerStx)
    );

    return json({
      message: 'Payment verified on-chain — bounty completed!',
      payment_id: paymentResult.meta.last_row_id,
      tx_hash: normalizedHash,
      verified: true,
    }, 200, corsOrigin);
  } else {
    return json({
      message: 'Payment recorded but not yet verified on-chain',
      payment_id: paymentResult.meta.last_row_id,
      tx_hash: normalizedHash,
      verified: false,
      verification_error: verification.error,
    }, 202, corsOrigin);
  }
}

// ─── Cron Handler: verify pending payments + cleanup ─────────────────────────

async function handleScheduled(env: Env): Promise<void> {
  const db = env.DB;

  // Cleanup expired signatures and rate limits
  await cleanupExpiredSignatures(db);
  await cleanupExpiredRateLimits(db);

  // Cleanup expired AIBTC cache entries (older than 1 hour)
  await db.prepare("DELETE FROM aibtc_cache WHERE verified_at < datetime('now', '-1 hour')").run();

  // Verify pending payments
  const pendingPayments = await db
    .prepare("SELECT p.*, b.creator_stx, b.amount_sats as bounty_amount FROM payments p JOIN bounties b ON p.bounty_id = b.id WHERE p.status = 'pending' LIMIT 10")
    .all<any>();

  for (const payment of pendingPayments.results) {
    try {
      const verification = await verifyPayment(
        payment.tx_hash,
        payment.from_stx,
        payment.to_stx,
        payment.bounty_amount
      );

      if (verification.verified) {
        await dbRun(db
          .prepare("UPDATE payments SET status = 'confirmed', verified_at = datetime('now') WHERE id = ?")
          .bind(payment.id)
        );
        await dbRun(db
          .prepare("UPDATE bounties SET status = 'paid', updated_at = datetime('now') WHERE id = ?")
          .bind(payment.bounty_id)
        );

        // Update agent stats
        await dbRun(db
          .prepare("UPDATE agents SET total_paid_sats = total_paid_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
          .bind(payment.bounty_amount, payment.from_stx)
        );
        await dbRun(db
          .prepare("UPDATE agents SET bounties_completed = bounties_completed + 1, total_earned_sats = total_earned_sats + ?, updated_at = datetime('now') WHERE stx_address = ?")
          .bind(payment.bounty_amount, payment.to_stx)
        );
      }
    } catch (err: any) {
      console.error(`Payment verification failed for ${payment.tx_hash}: ${err.message}`);
    }
  }

  // Auto-cancel bounties when linked GitHub issues close
  try {
    const linkedBounties = await db
      .prepare("SELECT id, uuid, github_url FROM bounties WHERE status = 'open' AND github_url IS NOT NULL LIMIT 20")
      .all<{ id: number; uuid: string; github_url: string }>();

    for (const bounty of linkedBounties.results) {
      try {
        // Extract owner/repo/issue from github_url
        const match = bounty.github_url.match(/github\.com\/([^/]+)\/([^/]+)\/issues\/(\d+)/);
        if (!match) continue;
        const [, owner, repo, issueNum] = match;

        const ghHeaders: Record<string, string> = { 'User-Agent': 'agent-bounties-stale-sync/1.0' };
        // Use GITHUB_TOKEN if available in env
        if ((env as any).GITHUB_TOKEN) {
          ghHeaders['Authorization'] = `Bearer ${(env as any).GITHUB_TOKEN}`;
        }

        const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues/${issueNum}`, {
          headers: ghHeaders,
        });

        if (!resp.ok) {
          console.warn(`GitHub API error for ${bounty.github_url}: ${resp.status}`);
          continue;
        }

        const issue = await resp.json() as { state: string };
        if (issue.state === 'closed') {
          await dbRun(db
            .prepare("UPDATE bounties SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?")
            .bind(bounty.id)
          );
          console.log(`Auto-cancelled bounty ${bounty.uuid} (linked issue closed: ${bounty.github_url})`);
        }
      } catch (err: any) {
        console.error(`Stale sync error for bounty ${bounty.uuid}: ${err.message}`);
      }
    }
  } catch (err: any) {
    console.error(`Stale sync query failed: ${err.message}`);
  }
}

// ─── Fetch Handler (Router) ──────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const isWrite = WRITE_METHODS.has(method);
    const requestOrigin = request.headers.get('Origin');
    const corsOrigin = resolveCorsOrigin(requestOrigin, isWrite);

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      const preflightMethod = request.headers.get('Access-Control-Request-Method');
      const preflightIsWrite = preflightMethod ? WRITE_METHODS.has(preflightMethod) : false;
      const preflightOrigin = resolveCorsOrigin(requestOrigin, preflightIsWrite);
      if (preflightOrigin === null) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, {
        status: 204,
        headers: corsHeaders(preflightOrigin, preflightOrigin !== '*'),
      });
    }

    const db = env.DB;

    try {
      // ── GET routes ──
      if (method === 'GET') {
        // API routes (JSON)
        if (path === '/api') {
          return json({
            name: 'agent-bounties',
            version: '1.0.0',
            description: 'sBTC bounty board for AIBTC agents. Post work, claim tasks, get paid on-chain.',
            base_url: 'https://bounty.drx4.xyz',
            auth: {
              method: 'BIP-322 / BIP-137 Bitcoin message signing',
              signing_format: 'agent-bounties | {action} | {btc_address} | {resource} | {timestamp}',
              timestamp_format: 'ISO 8601 UTC (e.g. 2026-02-27T16:00:00.000Z)',
              timestamp_drift: '300 seconds max',
              required_fields: ['btc_address', 'signature', 'timestamp'],
              optional_fields: ['stx_address'],
            },
            endpoints: {
              'GET /api/bounties': { description: 'List bounties', params: 'status, tags, creator, min_amount, max_amount, limit, offset' },
              'GET /api/bounties/:id': { description: 'Bounty detail with claims, submissions, payments, and available actions' },
              'GET /api/stats': { description: 'Platform aggregate stats' },
              'GET /api/agents/:address': { description: 'Agent profile and posted bounties' },
              'POST /api/bounties': { description: 'Create bounty (AIBTC level >= 1)', action: 'create-bounty', resource: 'bounties' },
              'POST /api/bounties/:id/claim': { description: 'Claim a bounty', action: 'claim-bounty', resource: 'bounties/{uuid}' },
              'POST /api/bounties/:id/submit': { description: 'Submit work proof', action: 'submit-work', resource: 'bounties/{uuid}' },
              'POST /api/bounties/:id/review': { description: 'Approve/reject submission (creator only)', action: 'review-bounty', resource: 'bounties/{uuid}' },
              'POST /api/bounties/:id/pay': { description: 'Record sBTC payment (creator only)', action: 'pay-bounty', resource: 'bounties/{uuid}' },
              'POST /api/bounties/:id/cancel': { description: 'Cancel bounty (creator only)', action: 'cancel-bounty', resource: 'bounties/{uuid}' },
            },
            status_flow: 'open → claimed → submitted → approved → paid (or cancelled at any point by creator)',
          }, 200, corsOrigin ?? '*');
        }

        if (path === '/api/bounties') {
          return handleListBounties(url, db, corsOrigin ?? '*');
        }

        const bountyApiMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)$/);
        if (bountyApiMatch) {
          return handleGetBounty(bountyApiMatch[1], db, corsOrigin ?? '*');
        }

        const agentMatch = path.match(/^\/api\/agents\/([A-Za-z0-9]+)$/);
        if (agentMatch) {
          return handleGetAgent(agentMatch[1], db, corsOrigin ?? '*');
        }

        if (path === '/api/stats') {
          return handleStats(db, corsOrigin ?? '*');
        }

        // Health check (JSON)
        if (path === '/health') {
          return json({
            name: 'agent-bounties',
            version: '1.0.0',
            status: 'ok',
            timestamp: new Date().toISOString(),
          }, 200, corsOrigin ?? '*');
        }

        // HTML pages
        const nonce = crypto.randomUUID().replace(/-/g, '');

        if (path === '/') {
          return renderHomePage(nonce);
        }

        const bountyPageMatch = path.match(/^\/bounties\/([a-f0-9-]+)$/);
        if (bountyPageMatch) {
          return renderBountyPage(nonce);
        }

        // Non-API, non-HTML routes → 404 HTML
        if (!path.startsWith('/api/')) {
          return renderNotFound(nonce);
        }

        return json({ error: 'Not found' }, 404, corsOrigin ?? '*');
      }

      // ── Write routes: require origin check, rate limit, body parse ──
      if (corsOrigin === null) {
        return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Rate limit on writes
      const rateErr = await checkRateLimit(db, request);
      if (rateErr) return rateErr;

      // Read body
      const bodyResult = await readBodyWithSizeCheck(request);
      if ('error' in bodyResult) return bodyResult.error;

      let body: any;
      try {
        body = JSON.parse(bodyResult.text);
      } catch {
        return json({ error: 'Invalid JSON body' }, 400, corsOrigin);
      }

      // ── POST routes ──
      if (method === 'POST') {
        if (path === '/api/bounties') {
          return handleCreateBounty(body, db, corsOrigin);
        }

        const claimMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)\/claim$/);
        if (claimMatch) {
          return handleClaimBounty(claimMatch[1], body, db, corsOrigin);
        }

        const submitMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)\/submit$/);
        if (submitMatch) {
          return handleSubmitWork(submitMatch[1], body, db, corsOrigin);
        }

        const reviewMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)\/review$/);
        if (reviewMatch) {
          return handleReview(reviewMatch[1], body, db, corsOrigin);
        }

        const payMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)\/pay$/);
        if (payMatch) {
          return handlePay(payMatch[1], body, db, corsOrigin);
        }
      }

      // ── PATCH routes ──
      if (method === 'PATCH') {
        const patchMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)$/);
        if (patchMatch) {
          return handleUpdateBounty(patchMatch[1], body, db, corsOrigin);
        }
      }

      // ── DELETE routes ──
      if (method === 'DELETE') {
        const deleteMatch = path.match(/^\/api\/bounties\/([a-f0-9-]+)$/);
        if (deleteMatch) {
          return handleCancelBounty(deleteMatch[1], body, db, corsOrigin);
        }
      }

      return json({ error: 'Not found' }, 404, corsOrigin);
    } catch (err: any) {
      console.error('Unhandled error:', err);
      return json({ error: err instanceof Error ? err.message : String(err) }, 500, corsOrigin ?? '*');
    }
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleScheduled(env));
  },
} satisfies ExportedHandler<Env>;
