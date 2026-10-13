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
 * Fail-closed storage design (this registry is the last line of defense
 * against oracle key recovery, so every failure mode refuses to sign):
 *
 * 1. SINGLE WRITER FOR PROCESS LIFETIME. An O_EXCL lockfile next to the
 *    registry is taken at construction and held until close(). A second
 *    registry instance - in this process or any other - that opens the same
 *    file FAILS AT STARTUP with NonceRegistryLockError. Previously each
 *    instance kept its own in-memory map and rewrote the whole file on save,
 *    so two instances on one file both accepted the same nonce and the second
 *    save() erased the first's record: two signatures with the same k, i.e.
 *    oracle key recovery. A lock owned by a live process is never taken over;
 *    a lock whose owner died is taken over once, carrying its history digest
 *    forward (see 3).
 *
 * 2. DURABLE ATOMIC WRITES. Every save writes a temporary file, fsyncs it,
 *    renames()s it over the registry and fsyncs the directory. A crash can
 *    never leave a torn or empty registry behind.
 *
 * 3. HISTORY CANNOT BE RESET BY DELETION. The registry is an append-only log
 *    of records chained by digest: entry[i].chain = sha256(entry[i-1].chain ||
 *    sha256(entry[i])). Truncating, reordering or rewriting entries breaks
 *    the chain and the registry refuses to load. The lockfile additionally
 *    carries the chain tip: if the registry file disappears while the
 *    lockfile still records history, startup fails ("history destroyed")
 *    instead of silently starting from scratch - which would allow every
 *    previously used nonce to be used again.
 *
 * 4. NO IN-MEMORY-ONLY MODE OUTSIDE DEVELOPMENT. `persistPath: null` is only
 *    accepted with an explicit `allowInMemory: true` opt-in (the attestation
 *    engine only grants it in development mode on non-mainnet networks).
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/** Default on-disk location of the used-nonce registry */
export const DEFAULT_NONCE_REGISTRY_PATH = "data/used-nonces.json";

/** Chain seed of the append-only log (chain of the zeroth entry) */
const GENESIS_DIGEST = Buffer.alloc(32).toString("hex");

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

/**
 * Thrown when the registry cannot guarantee single-writer access or the
 * integrity of its history. Always fatal: the caller must not sign.
 */
export class NonceRegistryLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NonceRegistryLockError";
  }
}

/** A single append-only log entry */
interface LogEntry {
  /** Hex identifier of the derived nonce (its public point) */
  nonceId: string;
  /** Event the nonce was used for */
  eventId: string;
  /** Hex-encoded 32-byte digest that was signed */
  messageHash: string;
  /** Hex sha256(previous chain || sha256(nonceId || eventId || messageHash)) */
  chain: string;
}

interface PersistedShape {
  version: number;
  entries: LogEntry[];
}

/** Contents of the single-writer lockfile */
interface LockInfo {
  pid: number;
  hostname: string;
  acquiredAt: string;
  /** Random per-acquisition token; proves the lock file is still ours */
  token: string;
  /** Chain tip of the log when the lock was last touched (null = no history) */
  historyDigest: string | null;
  /**
   * Set by close(): the writer released the lock but the record (and its
   * history digest) is kept as the external anchor that lets tail truncation
   * of the log be detected on the next startup.
   */
  released?: boolean;
}

export interface UsedNonceRegistryOptions {
  /**
   * JSON file to persist to. Omit for the default
   * ("data/used-nonces.json").
   */
  persistPath?: string | null;
  /**
   * Explicit opt-in for in-memory-only operation (`persistPath: null`).
   * Refused otherwise: a restart of an in-memory registry forgets every
   * used nonce, which is exactly the nonce-reuse condition. Only the
   * development-mode attestation engine sets this.
   */
  allowInMemory?: boolean;
}

/**
 * Registry of used signing nonces.
 */
export class UsedNonceRegistry {
  private readonly entries: Map<string, NonceRecord> = new Map();
  /** Append-only persisted log (same order as insertion) */
  private readonly log: LogEntry[] = [];
  private readonly persistPath: string | null;
  private lockToken: string | null = null;

  constructor(options: UsedNonceRegistryOptions = {}) {
    const persistPath =
      options.persistPath === undefined ? DEFAULT_NONCE_REGISTRY_PATH : options.persistPath;

    if (persistPath === null) {
      if (options.allowInMemory !== true) {
        throw new NonceRegistryLockError(
          "UsedNonceRegistry: in-memory-only operation (persistPath: null) is refused outside " +
            "development: a restart forgets every used nonce and the deterministic derivation " +
            "would then sign twice with the same k, leaking the oracle key. Pass a persistent " +
            "path, or explicitly opt in with allowInMemory in development."
        );
      }
      this.persistPath = null;
      return;
    }

    this.persistPath = persistPath;
    fs.mkdirSync(path.dirname(persistPath), { recursive: true });

    // Single writer for the lifetime of this instance (fail startup if held).
    const lock = this.acquireLock();
    this.lockToken = lock.token;
    try {
      this.load(lock.historyDigest);
    } catch (e) {
      // Startup failed AFTER taking the lock: release it again - preserving
      // the inherited history-tip anchor, never re-deriving it from a
      // possibly truncated log - so a failed startup cannot wedge the file
      // and cannot launder tampered history into the anchor.
      this.releaseLockPreservingAnchor(lock.historyDigest);
      throw e;
    }
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

    const previousChain = this.log.length > 0 ? this.log[this.log.length - 1]!.chain : "";
    const entry: LogEntry = { nonceId, eventId, messageHash, chain: "" };
    entry.chain = this.chainDigest(previousChain, entry);
    this.entries.set(nonceId, { eventId, messageHash });
    this.log.push(entry);
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

  /**
   * Releases the single-writer lock. The registry keeps its full chained
   * history on disk and the lock RECORD is kept (marked `released`) so the
   * history tip remains an external anchor: truncating the log even after a
   * clean shutdown is still detected on the next startup. Only a live,
   * unreleased lock blocks a new instance.
   */
  close(): void {
    if (this.persistPath === null || this.lockToken === null) {
      return;
    }
    this.assertLockOwnership();
    this.writeLock({
      pid: process.pid,
      hostname: os.hostname(),
      acquiredAt: new Date().toISOString(),
      token: this.lockToken,
      historyDigest: this.log.length > 0 ? this.log[this.log.length - 1]!.chain : null,
      released: true,
    });
    this.lockToken = null;
  }

  // ------------------------------------------------------------------
  // Locking
  // ------------------------------------------------------------------

  private lockPath(): string {
    return `${this.persistPath!}.lock`;
  }

  /**
   * Takes the single-writer O_EXCL lock and holds it for this process.
   *
   * - If the lockfile exists and its owner is a live process (or a host we
   *   cannot check), startup FAILS: two writers would both accept a nonce
   *   and the second write would erase the first record.
   * - If the owner died, the lock is stale: it is taken over exactly once,
   *   carrying its recorded history digest forward so a deleted registry
   *   cannot be silently forgotten.
   * - A lockfile that exists but cannot be parsed is treated as held and
   *   fatal (never silently ignored).
   */
  private acquireLock(): LockInfo {
    const lockPath = this.lockPath();
    const token = crypto.randomBytes(16).toString("hex");
    let carriedDigest: string | null = null;

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = fs.openSync(lockPath, "wx", 0o600);
        const info: LockInfo = {
          pid: process.pid,
          hostname: os.hostname(),
          acquiredAt: new Date().toISOString(),
          token,
          historyDigest: carriedDigest,
        };
        const payload = Buffer.from(JSON.stringify(info, null, 2), "utf8");
        fs.writeSync(fd, payload, 0, payload.length, 0);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        // A racing recoverer must not have replaced our lock in the meantime.
        this.lockToken = token;
        this.assertLockOwnership();
        return info;
      } catch (e) {
        if (e instanceof NonceRegistryLockError) {
          throw e;
        }
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new NonceRegistryLockError(
            `UsedNonceRegistry: cannot create lock ${lockPath}: ${
              e instanceof Error ? e.message : String(e)
            }`
          );
        }

        let existing: LockInfo;
        try {
          const raw = fs.readFileSync(lockPath, "utf8");
          const parsed = JSON.parse(raw) as LockInfo;
          if (
            !parsed ||
            typeof parsed.pid !== "number" ||
            typeof parsed.token !== "string" ||
            typeof parsed.hostname !== "string"
          ) {
            throw new Error("malformed lock record");
          }
          existing = parsed;
        } catch (readError) {
          throw new NonceRegistryLockError(
            `UsedNonceRegistry: lock ${lockPath} exists but cannot be read ` +
              `(${readError instanceof Error ? readError.message : String(readError)}). ` +
              `Refusing to start: a second writer would allow nonce reuse and oracle key recovery.`
          );
        }

        // A lock explicitly released by its writer is free to take over.
        const released = existing.released === true;
        if (!released) {
          if (existing.hostname === os.hostname() && this.isPidAlive(existing.pid)) {
            throw new NonceRegistryLockError(
              `UsedNonceRegistry: ${this.persistPath} is locked by live process pid ` +
                `${existing.pid} (since ${existing.acquiredAt}). Refusing to start: two ` +
                `writers would allow the same derived nonce to sign twice and leak the oracle key.`
            );
          }
          if (existing.hostname !== os.hostname()) {
            throw new NonceRegistryLockError(
              `UsedNonceRegistry: ${this.persistPath} is locked by pid ${existing.pid} on ` +
                `host "${existing.hostname}", whose liveness cannot be verified from ` +
                `"${os.hostname()}". Refusing to start.`
            );
          }
        }

        // Stale (owner dead) or released lock: take it over once, carrying
        // the recorded history digest forward so deletion or truncation of
        // the registry cannot reset the nonce history.
        carriedDigest = existing.historyDigest;
        try {
          fs.unlinkSync(lockPath);
        } catch (unlinkError) {
          if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") {
            throw unlinkError;
          }
        }
      }
    }

    throw new NonceRegistryLockError(
      `UsedNonceRegistry: could not acquire ${lockPath} (contention). Refusing to start.`
    );
  }

  /**
   * Releases the lock after a failed startup, keeping the EXISTING
   * history-tip anchor (never recomputed from partially loaded state).
   */
  private releaseLockPreservingAnchor(anchor: string | null): void {
    try {
      this.writeLock({
        pid: process.pid,
        hostname: os.hostname(),
        acquiredAt: new Date().toISOString(),
        token: this.lockToken ?? "rolled-back",
        historyDigest: anchor,
        released: true,
      });
    } catch {
      // best-effort: the pid-liveness check still recovers a leaked lock
    }
    this.lockToken = null;
  }

  /**
   * Verifies the lockfile still belongs to this instance before any write.
   * If the lock was stolen (or the file replaced), we must not persist: a
   * concurrent writer's records would be silently erased.
   */
  private assertLockOwnership(): void {
    const lockPath = this.lockPath();
    let info: LockInfo;
    try {
      info = JSON.parse(fs.readFileSync(lockPath, "utf8")) as LockInfo;
    } catch (e) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: lost the single-writer lock on ${this.persistPath} ` +
          `(lock file unreadable); refusing to persist nonce state.`
      );
    }
    if (info.token !== this.lockToken || info.pid !== process.pid) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: lost the single-writer lock on ${this.persistPath} ` +
          `(held by pid ${info.pid}); refusing to persist nonce state.`
      );
    }
  }

  private isPidAlive(pid: number): boolean {
    if (!Number.isInteger(pid) || pid <= 0) {
      return false;
    }
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      // EPERM: exists but owned by another user - treat as alive.
      return (e as NodeJS.ErrnoException).code === "EPERM";
    }
  }

  // ------------------------------------------------------------------
  // Persistence
  // ------------------------------------------------------------------

  /** Digest chain: sha256(previous chain || sha256(record fields)) */
  private chainDigest(
    previousChain: string,
    entry: Pick<LogEntry, "nonceId" | "eventId" | "messageHash">
  ): string {
    const previous = previousChain === "" ? GENESIS_DIGEST : previousChain;
    const record = crypto
      .createHash("sha256")
      .update(`${entry.nonceId}\n${entry.eventId}\n${entry.messageHash}`, "utf8")
      .digest("hex");
    return crypto
      .createHash("sha256")
      .update(previous + record, "utf8")
      .digest("hex");
  }

  /**
   * Loads the append-only log and verifies its integrity.
   *
   * @param carriedDigest - chain tip recorded by the (stale) lock we took
   *   over, or null if there was no previous lock. Cross-checked against the
   *   log so that deleting the registry behind a lock cannot reset history.
   */
  private load(carriedDigest: string | null): void {
    const fileExists = fs.existsSync(this.persistPath!);

    if (!fileExists) {
      if (carriedDigest !== null) {
        throw new NonceRegistryLockError(
          `UsedNonceRegistry: ${this.persistPath} is missing but the lock file records ` +
            `nonce history (digest ${carriedDigest}). Refusing to start: the used-nonce ` +
            `history was deleted while the registry was locked, which would allow nonce ` +
            `reuse and oracle key recovery.`
        );
      }
      return;
    }

    let parsed: PersistedShape;
    try {
      parsed = JSON.parse(fs.readFileSync(this.persistPath!, "utf8")) as PersistedShape;
      if (!parsed || !Array.isArray(parsed.entries)) {
        throw new Error("malformed registry payload");
      }
    } catch (e) {
      // A corrupt registry must not silently allow nonce reuse: fail closed.
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: cannot read ${this.persistPath}: ${e instanceof Error ? e.message : String(e)}`
      );
    }

    // Verify the digest chain link by link: truncation, reordering or
    // rewriting of entries is detected.
    let chain = "";
    for (const entry of parsed.entries) {
      if (
        !entry ||
        typeof entry.nonceId !== "string" ||
        typeof entry.eventId !== "string" ||
        typeof entry.messageHash !== "string" ||
        typeof entry.chain !== "string"
      ) {
        throw new NonceRegistryLockError(
          `UsedNonceRegistry: ${this.persistPath} contains a malformed entry; refusing to continue.`
        );
      }
      const expected = this.chainDigest(chain, entry);
      if (expected !== entry.chain) {
        throw new NonceRegistryLockError(
          `UsedNonceRegistry: ${this.persistPath} failed its digest-chain check at nonce ` +
            `${entry.nonceId}: the used-nonce history was truncated, reordered or rewritten. ` +
            `Refusing to continue (nonce reuse would leak the oracle key).`
        );
      }
      chain = entry.chain;
      if (!this.entries.has(entry.nonceId)) {
        this.entries.set(entry.nonceId, { eventId: entry.eventId, messageHash: entry.messageHash });
        this.log.push({ ...entry });
      }
    }

    const tip = chain === "" ? null : chain;
    if (carriedDigest !== null && carriedDigest !== tip) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: lock file and ${this.persistPath} disagree about the nonce ` +
          `history tip (lock: ${carriedDigest}, log: ${tip ?? "(empty)"}). The registry ` +
          `was modified or reset behind the lock; refusing to continue.`
        );
    }
  }

  /**
   * Persists the log durably: temp file + fsync + rename + directory fsync.
   * Never writes a payload that does not contain every recorded nonce.
   */
  private save(): void {
    if (this.persistPath === null) {
      return;
    }
    this.assertLockOwnership();

    const payload: PersistedShape = {
      version: 2,
      entries: this.log,
    };
    const body = Buffer.from(JSON.stringify(payload, null, 2), "utf8");

    // Write to a private temp file in the same directory, fsync, then
    // atomically rename over the registry.
    const tmpPath = `${this.persistPath}.tmp.${this.lockToken ?? "mem"}`;
    const fd = fs.openSync(tmpPath, "wx", 0o600);
    try {
      fs.writeSync(fd, body, 0, body.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, this.persistPath);

    // fsync the directory so the rename itself is durable.
    try {
      const dirFd = fs.openSync(path.dirname(this.persistPath), "r");
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
    } catch (e) {
      // Directory fsync is unsupported on some platforms; the rename is
      // still atomic, so continue.
    }

    this.updateLockDigest();
  }

  /** Atomically rewrites the lockfile (temp file + fsync + rename) */
  private writeLock(info: LockInfo): void {
    const lockPath = this.lockPath();
    const tmpPath = `${lockPath}.tmp.${this.lockToken ?? "init"}`;
    const body = Buffer.from(JSON.stringify(info, null, 2), "utf8");
    const fd = fs.openSync(tmpPath, "wx", 0o600);
    try {
      fs.writeSync(fd, body, 0, body.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, lockPath);
  }

  /** Keeps the lockfile's recorded history tip in sync with the log */
  private updateLockDigest(): void {
    const tip = this.log.length > 0 ? this.log[this.log.length - 1]!.chain : null;
    this.writeLock({
      pid: process.pid,
      hostname: os.hostname(),
      acquiredAt: new Date().toISOString(),
      token: this.lockToken!,
      historyDigest: tip,
    });
  }
}
