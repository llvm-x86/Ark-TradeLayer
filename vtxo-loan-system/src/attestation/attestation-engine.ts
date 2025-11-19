/**
 * Attestation Engine
 * 
 * Core module for creating and verifying cryptographic attestations.
 * Supports multiple attestation types for DLC loan contracts.
 */

import { BitcoinNetwork } from "bitcoin-networks";
import {
  derivePublicKey,
  deriveSchnorrPublicKey,
  schnorrSign,
  schnorrSignWithNonce,
  schnorrVerify,
  tweakPrivateKey,
} from "../crypto/bitcoin-primitives";
import {
  createTaggedHash,
  deriveNonceTweak,
  hashAnnouncement,
  hashAttestation,
} from "../crypto/tagged-hash";
import { KeyProvider } from "../keys/key-provider";

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
}

/**
 * Main attestation engine for DLC operations
 */
export class AttestationEngine {
  private network: BitcoinNetwork;
  private keyProvider: KeyProvider;
  private noncePurpose: number;
  private oraclePrivateKey?: Buffer;
  private oraclePublicKey?: Buffer;

  constructor(config: AttestationEngineConfig) {
    this.network = config.network;
    this.keyProvider = config.keyProvider;
    this.noncePurpose = config.noncePurpose ?? 585; // BIP-0085 style purpose
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
  }

  /**
   * Derives a nonce private key for a specific event and index
   */
  private async deriveNonceKey(eventId: string, index: number): Promise<Buffer> {
    const keyPath = `m/${this.noncePurpose}'/${this.network.coinType}'/0'/0/${index}`;
    const keyResult = await this.keyProvider.deriveKey(keyPath);

    if (keyResult.isErr()) {
      throw new Error(
        `Failed to derive nonce key for event ${eventId} index ${index}: ${keyResult.error.message}`
      );
    }

    return keyResult.value;
  }

  /**
   * Computes the k-value (signing nonce) for an event
   * 
   * k = privkey_base + H(R_base || eventId)
   * 
   * This ensures deterministic, unique nonces per event.
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

    const noncesNeeded = this.calculateNoncesNeeded(descriptor);
    const noncePoints: Buffer[] = [];

    // Generate nonce commitments (R-values)
    for (let i = 0; i < noncesNeeded; i++) {
      const kValue = await this.computeKValue(eventId, i);
      const rValue = deriveSchnorrPublicKey(kValue);
      noncePoints.push(rValue);
    }

    // Serialize announcement for signing
    const announcementData = this.serializeAnnouncementData(
      eventId,
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
    const outcomeString = outcome ? descriptor.outcomes[0] : descriptor.outcomes[1];

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
    return this.signOutcomes(announcement, [outcome]);
  }

  /**
   * Signs outcome messages with the corresponding nonces
   */
  private async signOutcomes(
    announcement: EventAnnouncement,
    outcomes: string[]
  ): Promise<EventAttestation> {
    if (!this.oraclePrivateKey) {
      throw new Error("Attestation engine not initialized");
    }

    const signatures: Buffer[] = [];

    for (let i = 0; i < outcomes.length; i++) {
      const kValue = await this.computeKValue(announcement.eventId, i);
      const outcomeHash = hashAttestation(outcomes[i]);
      const signature = schnorrSignWithNonce(
        this.oraclePrivateKey,
        outcomeHash,
        kValue
      );
      signatures.push(signature);
    }

    return {
      eventId: announcement.eventId,
      oraclePublicKey: this.oraclePublicKey!,
      outcomes,
      signatures,
      attestationTime: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Verifies an attestation against an announcement
   */
  verifyAttestation(
    announcement: EventAnnouncement,
    attestation: EventAttestation
  ): boolean {
    // Verify public keys match
    if (!announcement.oraclePublicKey.equals(attestation.oraclePublicKey)) {
      return false;
    }

    // Verify event IDs match
    if (announcement.eventId !== attestation.eventId) {
      return false;
    }

    // Verify outcome count matches signature count
    if (attestation.outcomes.length !== attestation.signatures.length) {
      return false;
    }

    // Verify each signature
    for (let i = 0; i < attestation.outcomes.length; i++) {
      const outcomeHash = hashAttestation(attestation.outcomes[i]);
      const valid = schnorrVerify(
        announcement.oraclePublicKey,
        outcomeHash,
        attestation.signatures[i]
      );

      if (!valid) {
        return false;
      }
    }

    return true;
  }

  /**
   * Serializes announcement data for signing
   */
  private serializeAnnouncementData(
    eventId: string,
    descriptor: EventDescriptor,
    maturityTime: number,
    noncePoints: Buffer[]
  ): Buffer {
    const parts: Buffer[] = [
      Buffer.from(eventId, "utf8"),
      Buffer.from(JSON.stringify(descriptor)),
      Buffer.alloc(8),
      ...noncePoints,
    ];

    // Write maturity time as big-endian 64-bit integer
    parts[2].writeBigInt64BE(BigInt(maturityTime), 0);

    return Buffer.concat(parts);
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
