/**
 * Used-Nonce Registry
 *
 * Persists every derived signing nonce that has been used for an attestation
 * and refuses to let the same nonce material be reused.
 *
 * Reusing a BIP-340 nonce k across two different signatures leaks the oracle
 * private key (x = (s1 - s2) / (e1 - e2)). The derivation in
 * attestation-engine.ts binds the eventId into the derivation path, but the
 * derivation itself is deterministic: if it were ever weakened, reset, or
 * collided, this registry is the fail-closed backstop.
 *
 * Policy: a derived nonce may only ever sign one (eventId, messageHash) pair.
 * Reuse for a DIFFERENT eventId - or for a different message under the same
 * eventId - is refused.
 *
 * Storage: in-memory map, optionally mirrored to a small JSON file so the
 * registry survives restarts (default "data/used-nonces.json").
 */

import * as fs from "fs";
import * as path from "path";

/** Default on-disk location of the used-nonce registry */
export const DEFAULT_NONCE_REGISTRY_PATH = "data/used-nonces.json";

/** A recorded nonce usage */
export interface NonceRecord {
  /** Event the nonce was used for */
  eventId: string;
  /** Hex-encoded 32-byte digest that was signed */
  messageHash: string;
}

/** Thrown when a derived nonce is about to be reused */
export class NonceReuseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NonceReuseError";
  }
}

interface PersistedShape {
  version: number;
  nonces: Record<string, NonceRecord>;
}

/**
 * Registry of used signing nonces.
 */
export class UsedNonceRegistry {
  private readonly entries: Map<string, NonceRecord> = new Map();
  private readonly persistPath: string | null;

  /**
   * @param persistPath - JSON file to persist to. Omit for the default
   *   ("data/used-nonces.json"); pass null for in-memory-only operation.
   */
  constructor(persistPath?: string | null) {
    this.persistPath =
      persistPath === undefined ? DEFAULT_NONCE_REGISTRY_PATH : persistPath;
    this.load();
  }

  /**
   * Checks that the nonce is unused (or was used for exactly the same
   * eventId + message) and records it. Throws NonceReuseError otherwise.
   *
   * @param nonceId - Hex identifier of the derived nonce (its public point)
   * @param eventId - Event being signed
   * @param messageHash - Hex digest being signed
   */
  checkAndRecord(nonceId: string, eventId: string, messageHash: string): void {
    const existing = this.entries.get(nonceId);
    if (existing) {
      if (existing.eventId !== eventId) {
        throw new NonceReuseError(
          `Refusing to sign: derived nonce ${nonceId} was already used for event ` +
            `"${existing.eventId}" and cannot be reused for event "${eventId}"`
        );
      }
      if (existing.messageHash !== messageHash) {
        throw new NonceReuseError(
          `Refusing to sign: derived nonce ${nonceId} for event "${eventId}" was ` +
            `already used to sign a different message (nonce reuse across messages ` +
            `would leak the oracle key)`
        );
      }
      // Identical (eventId, message): idempotent re-signing is safe.
      return;
    }

    this.entries.set(nonceId, { eventId, messageHash });
    this.save();
  }

  /** Returns the record for a nonce id, if any */
  get(nonceId: string): NonceRecord | undefined {
    return this.entries.get(nonceId);
  }

  /** Number of registered nonces */
  get size(): number {
    return this.entries.size;
  }

  private load(): void {
    if (!this.persistPath || !fs.existsSync(this.persistPath)) {
      return;
    }
    try {
      const raw = fs.readFileSync(this.persistPath, "utf8");
      const parsed = JSON.parse(raw) as PersistedShape;
      if (parsed && typeof parsed === "object" && parsed.nonces) {
        for (const [nonceId, record] of Object.entries(parsed.nonces)) {
          if (record && typeof record.eventId === "string" && typeof record.messageHash === "string") {
            this.entries.set(nonceId, record);
          }
        }
      }
    } catch (e) {
      // A corrupt registry must not silently allow nonce reuse: fail closed.
      throw new Error(
        `UsedNonceRegistry: cannot read ${this.persistPath}: ${e instanceof Error ? e.message : String(e)}`
      );
    }
  }

  private save(): void {
    if (!this.persistPath) {
      return;
    }
    const payload: PersistedShape = {
      version: 1,
      nonces: Object.fromEntries(this.entries),
    };
    const dir = path.dirname(this.persistPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.persistPath, JSON.stringify(payload, null, 2), "utf8");
  }
}
