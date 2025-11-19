/**
 * Bitcoin Cryptographic Primitives
 * 
 * Provides a clean interface for Bitcoin cryptographic operations,
 * wrapping cfd-js library with error handling and type safety.
 */

import * as cfdjs from "cfd-js";
import { randomBytes } from "crypto";

/** Represents a Bitcoin keypair with optional WIF encoding */
export interface KeyMaterial {
  privateKey: Buffer;
  publicKey: Buffer;
  wif?: string;
}

/** Configuration for key generation */
export interface KeyGenConfig {
  compressed?: boolean;
  network?: "mainnet" | "testnet" | "regtest";
}

/**
 * Generates a new random keypair
 */
export function generateKeypair(config: KeyGenConfig = {}): KeyMaterial {
  const { wif = false } = config;
  
  const request: cfdjs.CreateKeyPairRequest = { wif };
  const response = cfdjs.CreateKeyPair(request);
  
  return {
    privateKey: Buffer.from(response.privkey, "hex"),
    publicKey: Buffer.from(response.pubkey, "hex"),
    wif: response.wif,
  };
}

/**
 * Derives public key from private key
 */
export function derivePublicKey(privateKey: Buffer, compressed = true): Buffer {
  const request = {
    privkey: privateKey.toString("hex"),
    isCompressed: compressed,
  };
  
  const response = cfdjs.GetPubkeyFromPrivkey(request);
  return Buffer.from(response.pubkey, "hex");
}

/**
 * Derives Schnorr public key (x-only) from private key
 */
export function deriveSchnorrPublicKey(privateKey: Buffer): Buffer {
  const request = {
    privkey: privateKey.toString("hex"),
  };
  
  const response = cfdjs.GetSchnorrPubkeyFromPrivkey(request);
  return Buffer.from(response.pubkey, "hex");
}

/**
 * Extracts private key from WIF format
 */
export function privateKeyFromWif(wif: string): Buffer {
  const request = { wif };
  const response = cfdjs.GetPrivkeyFromWif(request);
  return Buffer.from(response.hex, "hex");
}

/**
 * Applies a tweak to a private key (for key path spending)
 */
export function tweakPrivateKey(privateKey: Buffer, tweak: Buffer): Buffer {
  const request = {
    privkey: privateKey.toString("hex"),
    tweak: tweak.toString("hex"),
  };
  
  const response = cfdjs.TweakAddPrivkey(request);
  return Buffer.from(response.privkey, "hex");
}

/**
 * Decodes a raw Bitcoin transaction
 */
export function decodeTransaction(rawTx: string): cfdjs.DecodeRawTransactionResponse {
  const request: cfdjs.DecodeRawTransactionRequest = {
    hex: rawTx,
  };
  
  return cfdjs.DecodeRawTransaction(request);
}

/**
 * Extracts locking script from a Bitcoin address
 */
export function addressToScript(address: string): string {
  const request = { address };
  const response = cfdjs.GetAddressInfo(request);
  return response.lockingScript;
}

/**
 * Creates a Schnorr signature using BIP340
 * 
 * @param privateKey - Private key for signing
 * @param message - Message digest (must be 32 bytes, pre-hashed)
 * @param auxiliaryRandom - Optional 32 bytes of randomness for nonce generation
 */
export function schnorrSign(
  privateKey: Buffer,
  message: Buffer,
  auxiliaryRandom?: Buffer
): Buffer {
  if (message.length !== 32) {
    throw new Error("Message must be exactly 32 bytes for Schnorr signing");
  }
  
  const request: cfdjs.SchnorrSignRequest = {
    privkey: privateKey.toString("hex"),
    nonceOrAux: (auxiliaryRandom || randomBytes(32)).toString("hex"),
    message: message.toString("hex"),
    isHashed: true,
  };
  
  const response = cfdjs.SchnorrSign(request);
  return Buffer.from(response.hex, "hex");
}

/**
 * Creates a Schnorr signature with a specific nonce
 * 
 * WARNING: Nonce reuse will leak the private key! Only use this
 * when implementing DLC adaptor signatures with deterministic nonces.
 * 
 * @param privateKey - Private key for signing
 * @param message - Message digest (32 bytes)
 * @param nonce - Deterministic nonce (32 bytes)
 */
export function schnorrSignWithNonce(
  privateKey: Buffer,
  message: Buffer,
  nonce: Buffer
): Buffer {
  if (message.length !== 32) {
    throw new Error("Message must be exactly 32 bytes");
  }
  if (nonce.length !== 32) {
    throw new Error("Nonce must be exactly 32 bytes");
  }
  
  const request: cfdjs.SchnorrSignRequest = {
    privkey: privateKey.toString("hex"),
    nonceOrAux: nonce.toString("hex"),
    message: message.toString("hex"),
    isHashed: true,
    isNonce: true,
  };
  
  const response = cfdjs.SchnorrSign(request);
  return Buffer.from(response.hex, "hex");
}

/**
 * Verifies a Schnorr signature
 * 
 * @returns true if signature is valid, false otherwise
 */
export function schnorrVerify(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer
): boolean {
  if (message.length !== 32) {
    throw new Error("Message must be exactly 32 bytes");
  }
  if (signature.length !== 64) {
    throw new Error("Schnorr signature must be exactly 64 bytes");
  }
  
  const request: cfdjs.SchnorrVerifyRequest = {
    pubkey: publicKey.toString("hex"),
    message: message.toString("hex"),
    signature: signature.toString("hex"),
    isHashed: true,
  };
  
  const response = cfdjs.SchnorrVerify(request);
  return response.valid;
}

/**
 * Error types for cryptographic operations
 */
export class CryptoError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "CryptoError";
  }
}

export class SignatureError extends CryptoError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "SignatureError";
  }
}

export class VerificationError extends CryptoError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "VerificationError";
  }
}
