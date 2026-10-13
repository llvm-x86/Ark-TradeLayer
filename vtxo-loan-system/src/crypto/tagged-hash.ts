/**
 * Tagged Hash Utilities
 * 
 * Implements BIP-340 tagged hashing for domain separation in Bitcoin protocols.
 * Used extensively in DLCs for nonce derivation and message signing.
 */

import { sha256 } from "@node-lightning/crypto";

/**
 * Cache for pre-computed tag hashes to avoid redundant computation
 */
const TAG_HASH_CACHE = new Map<string, Buffer>();

/**
 * Computes SHA256(tag) and caches the result
 */
function getOrComputeTagHash(tag: string | Buffer): Buffer {
  const tagKey = typeof tag === "string" ? tag : tag.toString("hex");
  
  let tagHash = TAG_HASH_CACHE.get(tagKey);
  if (!tagHash) {
    tagHash = sha256(Buffer.from(tag));
    TAG_HASH_CACHE.set(tagKey, tagHash);
  }
  
  return tagHash;
}

/**
 * Creates a tagged hash following BIP-340 specification
 * 
 * Tagged hash = SHA256(SHA256(tag) || SHA256(tag) || data)
 * 
 * This provides domain separation, ensuring that hashes for different
 * purposes cannot collide even with the same input data.
 * 
 * @param tag - Domain separation tag (e.g., "DLC/oracle/nonce/v0")
 * @param data - Data to hash
 * @returns 32-byte tagged hash
 */
export function createTaggedHash(tag: string | Buffer, data: Buffer): Buffer {
  const tagHash = getOrComputeTagHash(tag);
  const combined = Buffer.concat([tagHash, tagHash, data]);
  return sha256(combined);
}

/**
 * Standard tags used in DLC protocol
 *
 * NOTE: the attestation/announcement tags were bumped to v1 when the signed
 * messages were redefined as canonical length-prefixed commitments that bind
 * the eventId (see attestation-engine.ts). Signatures produced under the old
 * v0 tags are intentionally no longer valid.
 */
export const DLC_TAGS = {
  ORACLE_ANNOUNCEMENT: "DLC/oracle/announcement/v1",
  ORACLE_ATTESTATION: "DLC/oracle/attestation/v1",
  ORACLE_DESCRIPTOR: "DLC/oracle/descriptor/v1",
  ORACLE_NONCE: "DLC/oracle/nonce/v0",
  CONTRACT_INFO: "DLC/contract/info/v0",
  FUNDING_INPUT: "DLC/funding/input/v0",
} as const;

/**
 * Encodes a single field as a 4-byte big-endian length prefix followed by the
 * field bytes. Length-prefixing every field removes the concatenation
 * ambiguity that allows distinct field tuples to serialize to identical bytes.
 */
export function encodeLengthPrefixed(field: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(field.length, 0);
  return Buffer.concat([prefix, field]);
}

/**
 * Serializes fields as a canonical, unambiguous byte string:
 * each field is encoded as uint32_be(len(field)) || field.
 */
export function concatLengthPrefixed(fields: Buffer[]): Buffer {
  return Buffer.concat(fields.map(encodeLengthPrefixed));
}

/**
 * Encodes an unsigned integer as a fixed-width 8-byte big-endian value
 * (canonical integer serialization for hashed fields).
 */
export function encodeUint64BE(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`encodeUint64BE: value must be a non-negative safe integer, got ${value}`);
  }
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value), 0);
  return out;
}

/**
 * Creates announcement hash for oracle event pre-commitment
 *
 * @param announcementData - canonical length-prefixed announcement serialization
 */
export function hashAnnouncement(announcementData: Buffer): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ANNOUNCEMENT, announcementData);
}

/**
 * Creates attestation hash for oracle outcome signing
 *
 * @param message - canonical length-prefixed attestation serialization
 *   (eventId, oraclePubkey, descriptorHash, maturityTime, outcome). The
 *   outcome alone must never be signed: it is replayable across events.
 */
export function hashAttestation(message: Buffer): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ATTESTATION, message);
}

/**
 * Creates nonce tweak for deterministic R-value generation
 *
 * This is critical for DLC security - each event must have unique nonces
 * that can be deterministically regenerated for signing.
 *
 * Both fields are length-prefixed (previously they were concatenated raw,
 * so distinct (basePoint, eventId) tuples could serialize to the same bytes
 * and derive the same tweak - and therefore the same signing nonce k).
 *
 * @param basePoint - Base public point (typically the derived nonce point)
 * @param eventId - Unique event identifier
 */
export function deriveNonceTweak(basePoint: Buffer, eventId: string): Buffer {
  const combined = concatLengthPrefixed([basePoint, Buffer.from(eventId, "utf8")]);
  return createTaggedHash(DLC_TAGS.ORACLE_NONCE, combined);
}

/**
 * Clears the tag hash cache (useful for testing or memory management)
 */
export function clearTagHashCache(): void {
  TAG_HASH_CACHE.clear();
}

/**
 * Returns the current cache size (for monitoring)
 */
export function getTagHashCacheSize(): number {
  return TAG_HASH_CACHE.size;
}
