/**
 * Attestation Engine
 * 
 * Core module for creating and verifying cryptographic attestations.
 * Supports multiple attestation types for DLC loan contracts.
 */

import { BitcoinNetwork } from "bitcoin-networks";
import {
  deriveSchnorrPublicKey,
  schnorrSign,
  schnorrSignWithNonce,
  schnorrVerify,
  tweakPrivateKey,
} from "../crypto/bitcoin-primitives";
import {
  DLC_TAGS,
  concatLengthPrefixed,
  createTaggedHash,
  deriveNonceTweak,
  encodeUint64BE,
  hashAnnouncement,
  hashAttestation,
} from "../crypto/tagged-hash";
import { KeyProvider } from "../keys/key-provider";
import { UsedNonceRegistry } from "./used-nonce-registry";

export { NonceReuseError, UsedNonceRegistry } from "./used-nonce-registry";

/**
 * Maximum tolerated clock skew (seconds) past maturityTime before an
 * attestation is rejected as premature.
 */
export const MATURITY_SKEW_SECONDS = 300;

/**
 * Types of attestations supported
 */
export enum AttestationType {
  /** Numeric value (e.g., price, amount) */
  NUMERIC = "numeric",
  /** Binary outcome (e.g., paid/unpaid, yes/no) */
  BINARY = "binary",
  /** Enumerated outcome (e.g., fulfilled, defaulted, expired) */
  ENUM = "enum",
}

/**
 * Event descriptor for numeric attestations
 */
export interface NumericEventDescriptor {
  type: AttestationType.NUMERIC;
  /** Base for digit decomposition (typically 2 for binary) */
  base: number;
  /** Number of digits in decomposition */
  numDigits: number;
  /** Unit of measurement */
  unit: string;
  /** Decimal precision */
  precision: number;
  /** Whether the number can be negative */
  signed: boolean;
}

/**
 * Event descriptor for binary attestations
 */
export interface BinaryEventDescriptor {
  type: AttestationType.BINARY;
  /** Labels for true/false outcomes */
  outcomes: [string, string];
}

/**
 * Event descriptor for enum attestations
 */
export interface EnumEventDescriptor {
  type: AttestationType.ENUM;
  /** Possible outcome values */
  outcomes: string[];
}

export type EventDescriptor =
  | NumericEventDescriptor
  | BinaryEventDescriptor
  | EnumEventDescriptor;

/**
 * Pre-commitment to an oracle event
 */
export interface EventAnnouncement {
  /** Unique event identifier */
  eventId: string;
  /** Oracle's Schnorr public key */
  oraclePublicKey: Buffer;
  /** Event descriptor defining possible outcomes */
  descriptor: EventDescriptor;
  /** Maturity timestamp (Unix epoch seconds) */
  maturityTime: number;
  /** R-values (nonce commitments) for signing */
  noncePoints: Buffer[];
  /** Signature over the announcement by oracle */
  announcementSignature: Buffer;
}

/**
 * Cryptographic attestation to an event outcome
 */
export interface EventAttestation {
  /** Event ID this attests to */
  eventId: string;
  /** Oracle's public key */
  oraclePublicKey: Buffer;
  /** Actual outcome values */
  outcomes: string[];
  /** Schnorr signatures for each outcome */
  signatures: Buffer[];
  /** Timestamp when attestation was created */
  attestationTime: number;
}

/**
 * Configuration for attestation engine
 */
export interface AttestationEngineConfig {
  network: BitcoinNetwork;
  keyProvider: KeyProvider;
  /** HD path prefix for nonce derivation */
  noncePurpose?: number;
  /**
   * Trusted oracle x-only public key (32-byte Buffer or 64-char hex).
   * verifyAttestation refuses anything not signed by this key (C2).
   */
  trustedOraclePublicKey?: string | Buffer;
  /**
   * JSON file used to persist the used-nonce registry across restarts
   * (default "data/used-nonces.json"). Pass null for in-memory only.
   */
  usedNonceRegistryPath?: string | null;
}

/**
 * Canonical descriptor serialization (deterministic, length-prefixed).
 *
 * Replaces JSON.stringify(): JSON output is not canonical (key order,
 * whitespace) and was previously concatenated into an unsigned context,
 * making announcements malleable. Every field is encoded as
 * uint32_be(len) || utf8(field).
 */
export function serializeDescriptor(descriptor: EventDescriptor): Buffer {
  const str = (s: string): Buffer => Buffer.from(s, "utf8");
  const parts: Buffer[] = [];

  switch (descriptor.type) {
    case AttestationType.NUMERIC:
      parts.push(
        str("numeric"),
        str(String(descriptor.base)),
        str(String(descriptor.numDigits)),
        str(descriptor.unit),
        str(String(descriptor.precision)),
        str(descriptor.signed ? "1" : "0")
      );
      break;
    case AttestationType.BINARY: {
      const [labelTrue, labelFalse] = descriptor.outcomes;
      parts.push(str("binary"), str(labelTrue), str(labelFalse));
      break;
    }
    case AttestationType.ENUM:
      parts.push(str("enum"), ...descriptor.outcomes.map(str));
      break;
  }

  return concatLengthPrefixed(parts);
}

/**
 * Fixed-size (32-byte) commitment to an event descriptor.
 */
export function hashDescriptor(descriptor: EventDescriptor): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_DESCRIPTOR, serializeDescriptor(descriptor));
}

/**
 * Canonical attestation message (v1).
 *
 * The signed digest covers - in this exact order, each field prefixed with a
 * 4-byte big-endian length:
 *
 *   lenpfx(utf8(eventId))
 *   || lenpfx(oraclePubkeyXonly)          (32 raw bytes)
 *   || lenpfx(descriptorHash)             (32 raw bytes, see hashDescriptor)
 *   || lenpfx(maturityTime as uint64 BE)  (8 raw bytes)
 *   || lenpfx(utf8(outcome))
 *
 * Binding all five fields prevents cross-contract replay: a signature for one
 * (eventId, descriptor, maturity, outcome) tuple is invalid for any other.
 */
export function serializeAttestationMessage(
  eventId: string,
  oraclePublicKey: Buffer,
  descriptor: EventDescriptor,
  maturityTime: number,
  outcome: string
): Buffer {
  return concatLengthPrefixed([
    Buffer.from(eventId, "utf8"),
    oraclePublicKey,
    hashDescriptor(descriptor),
    encodeUint64BE(maturityTime),
    Buffer.from(outcome, "utf8"),
  ]);
}

/**
 * Canonical announcement message (v1): the attestation fields above with the
 * nonce pre-commitments appended, each length-prefixed:
 *
 *   lenpfx(utf8(eventId)) || lenpfx(oraclePubkeyXonly) || lenpfx(descriptorHash)
 *   || lenpfx(maturityTime as uint64 BE) || lenpfx(noncePoint[0]) || ...
 */
export function serializeAnnouncementMessage(
  eventId: string,
  oraclePublicKey: Buffer,
  descriptor: EventDescriptor,
  maturityTime: number,
  noncePoints: Buffer[]
): Buffer {
  return concatLengthPrefixed([
    Buffer.from(eventId, "utf8"),
    oraclePublicKey,
    hashDescriptor(descriptor),
    encodeUint64BE(maturityTime),
    ...noncePoints,
  ]);
}

/**
 * Parses a trusted oracle key (x-only, 32 bytes) from a Buffer or hex string.
 * Returns undefined for anything malformed.
 */
export function parseOraclePublicKey(key: string | Buffer | undefined): Buffer | undefined {
  if (key === undefined) {
    return undefined;
  }
  if (Buffer.isBuffer(key)) {
    return key.length === 32 ? Buffer.from(key) : undefined;
  }
  if (typeof key === "string" && /^[0-9a-fA-F]{64}$/.test(key)) {
    return Buffer.from(key, "hex");
  }
  return undefined;
}

/**
 * Main attestation engine for DLC operations
 */
export class AttestationEngine {
  private network: BitcoinNetwork;
  private keyProvider: KeyProvider;
  private noncePurpose: number;
  private trustedOraclePublicKey?: Buffer;
  private usedNonces: UsedNonceRegistry;
  private oraclePrivateKey?: Buffer;
  private oraclePublicKey?: Buffer;

  constructor(config: AttestationEngineConfig) {
    this.network = config.network;
    this.keyProvider = config.keyProvider;
    this.noncePurpose = config.noncePurpose ?? 585; // BIP-0085 style purpose
    this.trustedOraclePublicKey = parseOraclePublicKey(config.trustedOraclePublicKey);
    this.usedNonces = new UsedNonceRegistry(config.usedNonceRegistryPath);
  }

  /**
   * Initializes the oracle's master key
   */
  async initialize(): Promise<void> {
    // Derive master oracle key
    const keyPath = `m/48'/${this.network.coinType}'/0'/0'/0`;
    const keyResult = await this.keyProvider.deriveKey(keyPath);

    if (keyResult.isErr()) {
      throw new Error(`Failed to initialize oracle key: ${keyResult.error.message}`);
    }

    this.oraclePrivateKey = keyResult.value;
    this.oraclePublicKey = deriveSchnorrPublicKey(this.oraclePrivateKey);
    // Startup log of the derived oracle key (C3): operators must be able to
    // verify what is configured as the trusted key.
    console.log(
      `[oracle] Derived oracle public key (x-only): ${this.oraclePublicKey.toString("hex")}`
    );
  }

  /**
   * Computes the hardened BIP-32 index used to derive the nonce key for
   * (eventId, nonceIndex).
   *
   * The index is the first 31 bits of a tagged hash over the length-prefixed
   * (eventId, nonceIndex) pair - not a bare counter - so the derivation is
   * bound to the event and cannot be correlated across events. 31 bits keep
   * the index valid for hardened derivation (index < 2^31).
   */
  private computeNonceDerivationIndex(eventId: string, nonceIndex: number): number {
    const indexBuf = Buffer.alloc(4);
    indexBuf.writeUInt32BE(nonceIndex, 0);
    const digest = createTaggedHash(
      DLC_TAGS.ORACLE_NONCE,
      concatLengthPrefixed([Buffer.from(eventId, "utf8"), indexBuf])
    );
    return digest.readUInt32BE(0) & 0x7fffffff;
  }

  /**
   * Derives a nonce private key for a specific event and index
   *
   * Path: m/{purpose}'/{coinType}'/0'/0'/{index}' - fully hardened to avoid
   * cross-event correlation through unhardened extended public keys.
   */
  private async deriveNonceKey(eventId: string, nonceIndex: number): Promise<Buffer> {
    const index = this.computeNonceDerivationIndex(eventId, nonceIndex);
    const keyPath = `m/${this.noncePurpose}'/${this.network.coinType}'/0'/0'/${index}'`;
    const keyResult = await this.keyProvider.deriveKey(keyPath);

    if (keyResult.isErr()) {
      throw new Error(
        `Failed to derive nonce key for event ${eventId} index ${nonceIndex}: ${keyResult.error.message}`
      );
    }

    return keyResult.value;
  }

  /**
   * Computes the k-value (signing nonce) for an event
   * 
   * k = privkey_base + H(R_base || eventId)
   * 
   * This ensures deterministic, unique nonces per event. Both fields of the
   * tweak preimage are length-prefixed (see deriveNonceTweak).
   */
  private async computeKValue(eventId: string, index: number): Promise<Buffer> {
    const noncePrivKey = await this.deriveNonceKey(eventId, index);
    const noncePoint = deriveSchnorrPublicKey(noncePrivKey);
    const tweak = deriveNonceTweak(noncePoint, eventId);

    return tweakPrivateKey(this.oraclePrivateKey!, tweak);
  }

  /**
   * Calculates the number of nonces needed for an event descriptor
   */
  private calculateNoncesNeeded(descriptor: EventDescriptor): number {
    switch (descriptor.type) {
      case AttestationType.NUMERIC:
        // One nonce per digit, plus one for sign if signed
        return descriptor.numDigits + (descriptor.signed ? 1 : 0);
      case AttestationType.BINARY:
      case AttestationType.ENUM:
        // Single nonce for enum/binary outcomes
        return 1;
    }
  }

  /**
   * Checks that an outcome vector is consistent with the descriptor:
   * correct length, and every outcome inside the descriptor's declared
   * outcome set (digits of the declared base for numeric events, declared
   * labels for binary/enum events).
   */
  private outcomesMatchDescriptor(
    descriptor: EventDescriptor,
    outcomes: string[]
  ): boolean {
    if (outcomes.length !== this.calculateNoncesNeeded(descriptor)) {
      return false;
    }

    switch (descriptor.type) {
      case AttestationType.NUMERIC: {
        const { base, signed } = descriptor;
        if (!Number.isInteger(base) || base < 2 || base > 36) {
          return false;
        }
        const digits = new Set<string>();
        for (let d = 0; d < base; d++) {
          digits.add(d.toString(base));
        }
        let digitOutcomes = outcomes;
        if (signed) {
          const sign = outcomes[0];
          if (sign !== "+" && sign !== "-") {
            return false;
          }
          digitOutcomes = outcomes.slice(1);
        }
        return digitOutcomes.every((o) => o.length === 1 && digits.has(o));
      }
      case AttestationType.BINARY:
      case AttestationType.ENUM: {
        const outcome = outcomes[0];
        return outcome !== undefined && descriptor.outcomes.includes(outcome);
      }
    }
  }

  /**
   * Creates a new event announcement
   */
  async createAnnouncement(
    eventId: string,
    descriptor: EventDescriptor,
    maturityTime: number
  ): Promise<EventAnnouncement> {
    if (!this.oraclePrivateKey || !this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    if (!Number.isSafeInteger(maturityTime) || maturityTime <= 0) {
      throw new Error(`Invalid maturityTime: ${maturityTime}`);
    }

    const noncesNeeded = this.calculateNoncesNeeded(descriptor);
    const noncePoints: Buffer[] = [];

    // Generate nonce commitments (R-values)
    for (let i = 0; i < noncesNeeded; i++) {
      const kValue = await this.computeKValue(eventId, i);
      const rValue = deriveSchnorrPublicKey(kValue);
      noncePoints.push(rValue);
    }

    // Serialize announcement for signing (canonical, length-prefixed)
    const announcementData = serializeAnnouncementMessage(
      eventId,
      this.oraclePublicKey,
      descriptor,
      maturityTime,
      noncePoints
    );

    // Sign the announcement
    const announcementHash = hashAnnouncement(announcementData);
    const announcementSignature = schnorrSign(
      this.oraclePrivateKey,
      announcementHash
    );

    return {
      eventId,
      oraclePublicKey: this.oraclePublicKey,
      descriptor,
      maturityTime,
      noncePoints,
      announcementSignature,
    };
  }

  /**
   * Creates an attestation for a numeric event
   */
  async attestNumeric(
    announcement: EventAnnouncement,
    value: number
  ): Promise<EventAttestation> {
    if (announcement.descriptor.type !== AttestationType.NUMERIC) {
      throw new Error("Announcement is not numeric type");
    }

    const descriptor = announcement.descriptor;
    const { base, numDigits, signed } = descriptor;

    // Decompose value into digits
    const valueStr = Math.abs(value)
      .toString(base)
      .padStart(numDigits, "0");
    
    if (valueStr.length > numDigits) {
      throw new Error(`Value ${value} exceeds digit capacity`);
    }

    const outcomes = valueStr.split("");
    
    // Add sign if needed
    if (signed) {
      outcomes.unshift(value >= 0 ? "+" : "-");
    }

    return this.signOutcomes(announcement, outcomes);
  }

  /**
   * Creates an attestation for a binary event
   */
  async attestBinary(
    announcement: EventAnnouncement,
    outcome: boolean
  ): Promise<EventAttestation> {
    if (announcement.descriptor.type !== AttestationType.BINARY) {
      throw new Error("Announcement is not binary type");
    }

    const descriptor = announcement.descriptor;
    const [labelTrue, labelFalse] = descriptor.outcomes;
    const outcomeString = outcome ? labelTrue : labelFalse;

    return this.signOutcomes(announcement, [outcomeString]);
  }

  /**
   * Creates an attestation for an enum event
   */
  async attestEnum(
    announcement: EventAnnouncement,
    outcomeIndex: number
  ): Promise<EventAttestation> {
    if (announcement.descriptor.type !== AttestationType.ENUM) {
      throw new Error("Announcement is not enum type");
    }

    const descriptor = announcement.descriptor;
    
    if (outcomeIndex < 0 || outcomeIndex >= descriptor.outcomes.length) {
      throw new Error(`Invalid outcome index ${outcomeIndex}`);
    }

    const outcome = descriptor.outcomes[outcomeIndex];
    if (outcome === undefined) {
      throw new Error(`Invalid outcome index ${outcomeIndex}`);
    }
    return this.signOutcomes(announcement, [outcome]);
  }

  /**
   * Signs outcome messages with the corresponding nonces
   *
   * Each signature covers the canonical v1 attestation message binding
   * (eventId, oraclePubkey, descriptorHash, maturityTime, outcome), and every
   * derived nonce is checked against / recorded in the used-nonce registry
   * before signing.
   */
  private async signOutcomes(
    announcement: EventAnnouncement,
    outcomes: string[]
  ): Promise<EventAttestation> {
    if (!this.oraclePrivateKey || !this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    if (!announcement.oraclePublicKey.equals(this.oraclePublicKey)) {
      throw new Error("Announcement oracle key does not match this engine's key");
    }
    if (!this.outcomesMatchDescriptor(announcement.descriptor, outcomes)) {
      throw new Error(
        `Outcomes [${outcomes.join(", ")}] do not match the announcement descriptor`
      );
    }

    const signatures: Buffer[] = [];

    for (let i = 0; i < outcomes.length; i++) {
      const outcome = outcomes[i];
      if (outcome === undefined) {
        throw new Error(`Missing outcome at index ${i}`);
      }
      const message = serializeAttestationMessage(
        announcement.eventId,
        this.oraclePublicKey,
        announcement.descriptor,
        announcement.maturityTime,
        outcome
      );
      const messageHash = hashAttestation(message);

      // Registry check (H1): refuse if this derived nonce was already used.
      const noncePrivKey = await this.deriveNonceKey(announcement.eventId, i);
      const noncePoint = deriveSchnorrPublicKey(noncePrivKey);
      this.usedNonces.checkAndRecord(
        noncePoint.toString("hex"),
        announcement.eventId,
        messageHash.toString("hex")
      );

      const kValue = await this.computeKValue(announcement.eventId, i);
      const signature = schnorrSignWithNonce(
        this.oraclePrivateKey,
        messageHash,
        kValue
      );
      signatures.push(signature);
    }

    return {
      eventId: announcement.eventId,
      oraclePublicKey: this.oraclePublicKey,
      outcomes,
      signatures,
      attestationTime: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Verifies an attestation against an announcement
   *
   * Fail-closed checks (C2):
   *  (a) a trusted oracle key must be pinned (config/explicit argument) and
   *      both announcement and attestation must carry exactly that key;
   *  (b) the announcement itself must carry a valid oracle signature over the
   *      canonical v1 announcement message;
   *  (c) every signature's R must equal the announcement's pre-committed
   *      nonce point for that position;
   *  (d) the outcome vector must match the descriptor's declared outcome set
   *      and nonce count;
   *  (e) attestations for events that have not matured yet (beyond a small
   *      clock skew) are rejected.
   */
  verifyAttestation(
    announcement: EventAnnouncement,
    attestation: EventAttestation,
    trustedOraclePublicKey?: Buffer | string
  ): boolean {
    try {
      // (a) Pin the oracle key: self-consistency between the two supplied
      // objects is NOT sufficient - both must equal the trusted key.
      let trusted: Buffer | undefined;
      if (trustedOraclePublicKey !== undefined) {
        trusted = parseOraclePublicKey(trustedOraclePublicKey);
        if (!trusted) {
          return false; // fail closed: malformed explicit key
        }
      } else {
        trusted = this.trustedOraclePublicKey;
      }
      if (!trusted) {
        return false; // fail closed: no trusted oracle key configured
      }
      if (!announcement.oraclePublicKey.equals(trusted)) {
        return false;
      }
      if (!attestation.oraclePublicKey.equals(trusted)) {
        return false;
      }

      // Event IDs must match, and the attestation must be for this event
      if (announcement.eventId !== attestation.eventId) {
        return false;
      }

      if (!Number.isSafeInteger(announcement.maturityTime) || announcement.maturityTime <= 0) {
        return false;
      }

      // (e) Reject premature attestations (maturity in the future)
      const now = Math.floor(Date.now() / 1000);
      if (announcement.maturityTime > now + MATURITY_SKEW_SECONDS) {
        return false;
      }

      // (b) Verify the announcement signature over the canonical message
      if (announcement.announcementSignature.length !== 64) {
        return false;
      }
      const announcementHash = hashAnnouncement(
        serializeAnnouncementMessage(
          announcement.eventId,
          announcement.oraclePublicKey,
          announcement.descriptor,
          announcement.maturityTime,
          announcement.noncePoints
        )
      );
      if (!schnorrVerify(trusted, announcementHash, announcement.announcementSignature)) {
        return false;
      }

      // (d) Outcome vector must match the descriptor (count + declared set)
      const noncesNeeded = this.calculateNoncesNeeded(announcement.descriptor);
      if (announcement.noncePoints.length !== noncesNeeded) {
        return false;
      }
      if (
        attestation.outcomes.length !== noncesNeeded ||
        attestation.signatures.length !== noncesNeeded
      ) {
        return false;
      }
      if (!this.outcomesMatchDescriptor(announcement.descriptor, attestation.outcomes)) {
        return false;
      }

      // Verify each signature
      for (let i = 0; i < attestation.outcomes.length; i++) {
        const outcome = attestation.outcomes[i];
        const signature = attestation.signatures[i];
        const noncePoint = announcement.noncePoints[i];
        if (outcome === undefined || signature === undefined || noncePoint === undefined) {
          return false;
        }
        if (signature.length !== 64) {
          return false;
        }

        // (c) The signature's R must be the pre-committed nonce point
        if (!signature.slice(0, 32).equals(noncePoint)) {
          return false;
        }

        const messageHash = hashAttestation(
          serializeAttestationMessage(
            announcement.eventId,
            announcement.oraclePublicKey,
            announcement.descriptor,
            announcement.maturityTime,
            outcome
          )
        );
        const valid = schnorrVerify(trusted, messageHash, signature);
        if (!valid) {
          return false;
        }
      }

      return true;
    } catch (e) {
      // Malformed inputs must fail closed, not throw
      return false;
    }
  }

  /**
   * Gets the oracle's public key
   */
  getPublicKey(): Buffer {
    if (!this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    return this.oraclePublicKey;
  }
}
