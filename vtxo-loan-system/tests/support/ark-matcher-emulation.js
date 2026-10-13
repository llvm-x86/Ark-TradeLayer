/**
 * Independent re-implementation of the `.ark` on-chain matcher's canonical
 * attestation serialization (CollateralizedLoan.ark verifyOracleAttestation /
 * UnsecuredLoan.ark verifyRepayment).
 *
 * This module deliberately shares NO code with vtxo-loan-system/src: it is a
 * literal, byte-level transcription of the pseudo-code an on-chain matcher
 * would implement, used to prove that the TypeScript signer and the matcher
 * compute identical bytes. If either side changes, the shared vectors in
 * tests/vectors/attestation-vectors.json catch the divergence.
 *
 * Matcher semantics (from the .ark):
 *
 *   blob  := eventIdHash(32) || descriptorHash(32) || maturityTime(8 BE)
 *            || outcome(var) || signature(64)
 *
 *   message :=
 *     lenpfx(bytes(attestedEventId))   // 32-byte sha256(utf8(eventId))
 *     || lenpfx(bytes(xonly(oracleKey)))  // 32-byte x-only key
 *     || lenpfx(bytes(descriptorHash))    // 32 raw bytes
 *     || lenpfx(maturityTime)             // 8 bytes, uint64 BE
 *     || lenpfx(outcome)                  // utf8 bytes
 *
 *   messageHash := taggedHash("DLC/oracle/attestation/v1", message)
 *                = sha256(sha256(tag) || sha256(tag) || message)
 */
"use strict";

const crypto = require("crypto");

const ATTESTATION_TAG = "DLC/oracle/attestation/v1";

function sha256(...parts) {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}

function lenpfx(field) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(field.length, 0);
  return Buffer.concat([prefix, field]);
}

function taggedHash(tag, message) {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  return sha256(tagHash, tagHash, message);
}

function u64be(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value), 0);
  return out;
}

/**
 * Computes the matcher-side attestation message bytes.
 *
 * @param {{eventIdHash: Buffer, oracleKeyXonly: Buffer, descriptorHash: Buffer,
 *          maturityTime: number, outcome: Buffer}} fields
 * @returns {Buffer}
 */
function arkAttestationMessage(fields) {
  return Buffer.concat([
    lenpfx(fields.eventIdHash),
    lenpfx(fields.oracleKeyXonly),
    lenpfx(fields.descriptorHash),
    lenpfx(u64be(fields.maturityTime)),
    lenpfx(fields.outcome),
  ]);
}

/**
 * Computes the matcher-side attestation message hash (what the oracle signs
 * and what checkSchnorrSig verifies against).
 */
function arkAttestationMessageHash(fields) {
  return taggedHash(ATTESTATION_TAG, arkAttestationMessage(fields));
}

/** sha256(utf8(eventId)) - the pinned bytes32 event id of the contracts */
function arkEventIdHash(eventId) {
  return sha256(Buffer.from(eventId, "utf8"));
}

/**
 * Builds the v1 attestation blob the matcher parses:
 *   eventIdHash(32) || descriptorHash(32) || maturityTime(8) || outcome(var) || signature(64)
 */
function arkAttestationBlob(fields, signature) {
  return Buffer.concat([
    fields.eventIdHash,
    fields.descriptorHash,
    u64be(fields.maturityTime),
    fields.outcome,
    signature,
  ]);
}

module.exports = {
  ATTESTATION_TAG,
  arkAttestationMessage,
  arkAttestationMessageHash,
  arkAttestationBlob,
  arkEventIdHash,
  lenpfx,
  sha256,
  taggedHash,
  u64be,
};
