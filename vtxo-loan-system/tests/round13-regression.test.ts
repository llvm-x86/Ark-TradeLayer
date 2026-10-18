/**
 * Round-13 regression tests (review of the round-12 tree):
 *
 *  R13-1  a relative nonce registry path is refused, so the registry cannot
 *         depend on the working directory of the process
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine } from "../src/attestation/attestation-engine";
import { UsedNonceRegistry } from "../src/attestation/used-nonce-registry";
import { MockKeyProvider } from "../src/keys/key-provider";

const MNEMONIC = "test test test test test test test test test test test junk";

jest.setTimeout(60_000);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe("R13-1: a relative nonce registry path is refused", () => {
  it("the registry refuses a relative path and creates nothing in the working directory", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r13-relative-");
    process.chdir(scratch);
    try {
      expect(() => new UsedNonceRegistry({ persistPath: "data/used-nonces.json" })).toThrow(
        /absolute/
      );
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });

  it("the engine refuses a relative usedNonceRegistryPath at construction", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r13-relative-engine-");
    process.chdir(scratch);
    try {
      expect(
        () =>
          new AttestationEngine({
            network: BitcoinNetworks.bitcoin_regtest,
            keyProvider: new MockKeyProvider(MNEMONIC),
            usedNonceRegistryPath: "data/used-nonces.json",
            developmentMode: true,
          })
      ).toThrow(/absolute/);
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });

  it("an absolute path is accepted, and the same file is found from another directory", () => {
    const registryPath = path.join(tmpDir("r13-absolute-"), "data", "used-nonces.json");
    const previous = process.cwd();
    const first = new UsedNonceRegistry({ persistPath: registryPath });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.close();

    process.chdir(os.tmpdir());
    try {
      const restarted = new UsedNonceRegistry({ persistPath: registryPath });
      expect(() =>
        restarted.checkAndRecord("11".repeat(32), "event-1", "bb".repeat(32))
      ).toThrow(/nonce/i);
      restarted.close();
    } finally {
      process.chdir(previous);
    }
  });
});
