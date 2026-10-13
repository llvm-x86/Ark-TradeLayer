/**
 * Child process helper for cross-process used-nonce registry probes.
 *
 * usage: node registry-child.js <registryPath> <mode>
 *
 * Modes:
 *   record  - open the registry, record a nonce, then exit WITHOUT close()
 *             (simulates a crash: the single-writer lockfile must remain)
 *   hold    - open the registry, record a nonce, announce HELD, stay alive
 *   open    - open the registry and announce OPENED (fails loudly on refusal)
 */
"use strict";

require("./register.js");

const {
  UsedNonceRegistry,
  NonceRegistryLockError,
} = require("../../src/attestation/used-nonce-registry");

const [, , registryPath, mode] = process.argv;

try {
  const registry = new UsedNonceRegistry({ persistPath: registryPath });

  if (mode === "record") {
    registry.checkAndRecord("aa".repeat(32), "event-child", "bb".repeat(32));
    console.log("RECORDED");
    process.exit(0); // crash-style exit: no close(), lockfile stays
  }

  if (mode === "hold") {
    registry.checkAndRecord("cc".repeat(32), "event-hold", "dd".repeat(32));
    console.log("HELD");
    setTimeout(() => process.exit(0), 10_000);
    return;
  }

  if (mode === "open") {
    console.log("OPENED");
    process.exit(0);
  }

  console.error(`unknown mode: ${mode}`);
  process.exit(2);
} catch (e) {
  if (e instanceof NonceRegistryLockError || (e && e.name === "NonceRegistryLockError")) {
    console.log(`REFUSED: ${e.message}`);
    process.exit(3);
  }
  console.error(String(e && e.stack ? e.stack : e));
  process.exit(4);
}
