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
 */
export const DLC_TAGS = {
  ORACLE_ANNOUNCEMENT: "DLC/oracle/announcement/v0",
  ORACLE_ATTESTATION: "DLC/oracle/attestation/v0",
  ORACLE_NONCE: "DLC/oracle/nonce/v0",
  CONTRACT_INFO: "DLC/contract/info/v0",
  FUNDING_INPUT: "DLC/funding/input/v0",
} as const;

/**
 * Creates announcement hash for oracle event pre-commitment
 */
export function hashAnnouncement(announcementData: Buffer): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ANNOUNCEMENT, announcementData);
}

/**
 * Creates attestation hash for oracle outcome signing
 */
export function hashAttestation(outcome: string): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ATTESTATION, Buffer.from(outcome));
}

/**
 * Creates nonce tweak for deterministic R-value generation
 * 
 * This is critical for DLC security - each event must have unique nonces
 * that can be deterministically regenerated for signing.
 * 
 * @param basePoint - Base public point (typically oracle's public key)
 * @param eventId - Unique event identifier
 */
export function deriveNonceTweak(basePoint: Buffer, eventId: string): Buffer {
  const combined = Buffer.concat([basePoint, Buffer.from(eventId, "utf8")]);
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
