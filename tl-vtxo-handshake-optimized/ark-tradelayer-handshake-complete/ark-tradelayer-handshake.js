/**
 * Ark-TradeLayer Handshake Implementation
 * Following spec v0.1
 * 
 * This module handles template canonicity, deposit recognition, and exit validation
 * WITHOUT trying to parse the entire VTXO tree structure.
 */

const crypto = require('crypto');
const TxUtils = require('./txUtils.js');

/**
 * Template Canonicity Module
 */
class ArkTemplateRegistry {
  constructor() {
    // Map<templateId, ArkTemplate>
    this.templates = new Map();
    
    // Map<taprootOutputKey, { templateId, aspId }>
    // This is the O(1) lookup for deposit recognition
    this.outputKeyIndex = new Map();
    
    // Allowlist of (templateId, aspId) pairs
    // This is governance-controlled
    this.allowlist = new Set();
  }

  /**
   * Computes canonical templateId from ArkTemplate
   */
  computeTemplateId(template) {
    // Canonical serialization
    const canonical = {
      version: template.version,
      network: template.network,
      internalKey: template.internalKey,
      merkleRoot: template.merkleRoot,
      leafScripts: template.leafScripts.slice().sort(), // deterministic order
      leafVersions: template.leafVersions,
      leafRoles: template.leafRoles,
      timeouts: this.canonicalJSON(template.timeouts),
      semantics: this.canonicalJSON(template.semantics)
    };

    const serialized = Buffer.concat([
      Buffer.from('TL_ARK_TEMPLATE_V1', 'utf8'),
      Buffer.from(canonical.network, 'utf8'),
      Buffer.from(canonical.internalKey, 'hex'),
      Buffer.from(canonical.merkleRoot, 'hex'),
      Buffer.from(JSON.stringify({
        leafScripts: canonical.leafScripts,
        leafVersions: canonical.leafVersions,
        leafRoles: canonical.leafRoles,
        timeouts: canonical.timeouts,
        semantics: canonical.semantics
      }), 'utf8')
    ]);

    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Canonical JSON serialization (deterministic)
   */
  canonicalJSON(obj) {
    // Sort keys recursively
    const sortKeys = (o) => {
      if (typeof o !== 'object' || o === null) return o;
      if (Array.isArray(o)) return o.map(sortKeys);
      
      return Object.keys(o).sort().reduce((acc, key) => {
        acc[key] = sortKeys(o[key]);
        return acc;
      }, {});
    };
    
    return sortKeys(obj);
  }

  /**
   * Registers a template (after governance approval)
   */
  registerTemplate(template, aspId) {
    // 1. Compute templateId
    const templateId = this.computeTemplateId(template);
    
    // 2. Verify it matches declared templateId
    if (template.templateId && template.templateId !== templateId) {
      throw new Error(`Template ID mismatch: computed ${templateId}, declared ${template.templateId}`);
    }

    // 3. Verify taprootOutputKey is correct
    const computedKey = this.computeTaprootOutputKey(
      template.internalKey,
      template.merkleRoot
    );
    
    if (computedKey !== template.taprootOutputKey) {
      throw new Error(`Taproot output key mismatch: computed ${computedKey}, declared ${template.taprootOutputKey}`);
    }

    // 4. Store template
    template.templateId = templateId;
    this.templates.set(templateId, template);

    // 5. Index by output key for fast lookup
    this.outputKeyIndex.set(template.taprootOutputKey, {
      templateId,
      aspId
    });

    // 6. Add to allowlist
    this.allowlist.add(`${templateId}:${aspId}`);

    console.log(`[Template Registry] Registered template ${templateId} for ASP ${aspId}`);
    
    return templateId;
  }

  /**
   * Computes Taproot output key: Q = P + H(P || root)G
   */
  computeTaprootOutputKey(internalKeyHex, merkleRootHex) {
    // This is a simplified version - use bitcoinjs-lib or secp256k1 in production
    const internalKey = Buffer.from(internalKeyHex, 'hex');
    const merkleRoot = Buffer.from(merkleRootHex, 'hex');
    
    // t = H_taptweak(P || root)
    const tweak = crypto.createHash('sha256')
      .update(Buffer.concat([
        Buffer.from('TapTweak', 'utf8'),
        internalKey,
        merkleRoot
      ]))
      .digest();

    // Q = P + t*G (point addition)
    // For production, use proper secp256k1 library
    // This is a placeholder that returns a dummy key
    // In production: const Q = secp256k1.publicKeyTweakAdd(internalKey, tweak);
    
    console.warn('[WARNING] Using placeholder taproot key computation - implement with secp256k1 library');
    
    // Return placeholder for now
    return internalKey.toString('hex');
  }

  /**
   * Checks if a template is in the allowlist
   */
  isAllowed(templateId, aspId) {
    return this.allowlist.has(`${templateId}:${aspId}`);
  }

  /**
   * Gets template by ID
   */
  getTemplate(templateId) {
    return this.templates.get(templateId);
  }

  /**
   * Looks up template by taproot output key
   */
  findByOutputKey(taprootOutputKey) {
    return this.outputKeyIndex.get(taprootOutputKey);
  }
}

/**
 * Ark Deposit Recognition
 * 
 * Identifies when a Bitcoin UTXO is an Ark commitment for a known template
 */
class ArkDepositRecognizer {
  constructor(templateRegistry) {
    this.templateRegistry = templateRegistry;
  }

  /**
   * Checks if a UTXO is an Ark commitment
   * 
   * This is the critical function from the spec:
   * "isArkCommitmentUtxo() checks if a Bitcoin UTXO corresponds to known (templateId, aspId)"
   */
  isArkCommitmentUtxo(utxo) {
    try {
      // 1. Parse scriptPubKey - must be witness_v1_taproot
      const { version, program } = this.decodeSegwitOutput(utxo.scriptPubKey);
      
      if (version !== 1) {
        return null; // Not Taproot
      }

      if (program.length !== 32) {
        return null; // Invalid Taproot key length
      }

      const taprootOutputKey = program.toString('hex');

      // 2. Look up in template registry
      const match = this.templateRegistry.findByOutputKey(taprootOutputKey);
      
      if (!match) {
        return null; // Not a known template
      }

      // 3. Verify it's in the allowlist
      if (!this.templateRegistry.isAllowed(match.templateId, match.aspId)) {
        console.warn(`[Deposit Recognizer] Found template ${match.templateId} but not in allowlist`);
        return null;
      }

      return {
        templateId: match.templateId,
        aspId: match.aspId,
        taprootOutputKey,
        amount: utxo.value
      };

    } catch (error) {
      console.error('[Deposit Recognizer] Error checking UTXO:', error);
      return null;
    }
  }

  /**
   * Decodes a Segwit output scriptPubKey
   */
  decodeSegwitOutput(scriptPubKeyHex) {
    const script = Buffer.from(scriptPubKeyHex, 'hex');
    
    // Segwit format: OP_n <length> <program>
    // OP_0 = 0x00 (v0), OP_1 = 0x51 (v1), etc.
    
    if (script.length < 2) {
      throw new Error('Script too short');
    }

    let version;
    if (script[0] === 0x00) {
      version = 0;
    } else if (script[0] >= 0x51 && script[0] <= 0x60) {
      version = script[0] - 0x50;
    } else {
      throw new Error('Not a Segwit output');
    }

    const programLength = script[1];
    const program = script.slice(2, 2 + programLength);

    if (program.length !== programLength) {
      throw new Error('Program length mismatch');
    }

    return { version, program };
  }

  /**
   * Validates a deposit for TradeLayer minting
   */
  async validateDeposit(txid, vout, expectedAmount, minConfirmations = 6) {
    try {
      // 1. Get the transaction
      const tx = await TxUtils.getRawTransaction(txid, true);
      if (!tx) {
        throw new Error(`Transaction not found: ${txid}`);
      }

      // 2. Check confirmations
      if (!tx.confirmations || tx.confirmations < minConfirmations) {
        throw new Error(`Insufficient confirmations: ${tx.confirmations || 0} < ${minConfirmations}`);
      }

      // 3. Get the output
      const output = tx.vout[vout];
      if (!output) {
        throw new Error(`Output not found: ${txid}:${vout}`);
      }

      // 4. Check if it's an Ark commitment
      const commitment = this.isArkCommitmentUtxo({
        scriptPubKey: output.scriptPubKey.hex,
        value: output.value
      });

      if (!commitment) {
        throw new Error('Not a valid Ark commitment UTXO');
      }

      // 5. Verify amount
      const amountSats = Math.floor(output.value * 1e8);
      if (amountSats !== expectedAmount) {
        throw new Error(`Amount mismatch: expected ${expectedAmount}, got ${amountSats}`);
      }

      // 6. Check UTXO is unspent
      const isUnspent = await TxUtils.isUTXOUnspent(txid, vout);
      if (!isUnspent) {
        throw new Error('UTXO already spent');
      }

      return {
        valid: true,
        commitment,
        amountSats,
        confirmations: tx.confirmations
      };

    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
}

/**
 * Ark Exit Recognition
 * 
 * Validates script-path spends that represent user exits from Ark
 */
class ArkExitRecognizer {
  constructor(templateRegistry) {
    this.templateRegistry = templateRegistry;
  }

  /**
   * Validates an exit spend
   * 
   * From spec:
   * "Exit spends appear as Taproot scriptpath spends. TL protocol parses:
   *  - leaf script
   *  - control block
   *  - merkle path
   *  - checks taprootOutputKey reconstructed from leaf matches templateId"
   */
  async validateExit(spendingTxid, depositTxid, depositVout) {
    try {
      // 1. Get the spending transaction
      const spendingTx = await TxUtils.getRawTransaction(spendingTxid, true);
      if (!spendingTx) {
        throw new Error(`Spending transaction not found: ${spendingTxid}`);
      }

      // 2. Find the input that spends the deposit
      const spendingInput = spendingTx.vin.find(
        vin => vin.txid === depositTxid && vin.vout === depositVout
      );

      if (!spendingInput) {
        throw new Error('Spending input not found');
      }

      // 3. Check for witness data
      if (!spendingInput.txinwitness || spendingInput.txinwitness.length === 0) {
        throw new Error('No witness data');
      }

      // 4. Parse witness
      const witness = this.parseTaprootWitness(spendingInput.txinwitness);

      // 5. If key-path spend, this is not a user exit
      if (witness.spendType === 'key_path') {
        return {
          valid: false,
          reason: 'Key-path spend (not a user exit)'
        };
      }

      // 6. Extract leaf script and control block
      const { leafScript, controlBlock } = witness;

      // 7. Reconstruct merkle root and taproot key
      const reconstructed = this.reconstructTaprootKey(
        leafScript,
        controlBlock
      );

      // 8. Find matching template
      const match = this.templateRegistry.findByOutputKey(reconstructed.taprootOutputKey);
      
      if (!match) {
        return {
          valid: false,
          reason: 'Reconstructed key does not match any known template'
        };
      }

      // 9. Get template and verify this is a user-exit leaf
      const template = this.templateRegistry.getTemplate(match.templateId);
      
      const isUserExit = this.isUserExitLeaf(leafScript, template);
      
      if (!isUserExit) {
        return {
          valid: false,
          reason: 'Leaf script is not a user-exit leaf'
        };
      }

      // 10. Verify value release
      const releasedValue = this.getReleasedValue(spendingTx, spendingInput);

      return {
        valid: true,
        templateId: match.templateId,
        aspId: match.aspId,
        leafScript: leafScript.toString('hex'),
        releasedValue,
        confirmations: spendingTx.confirmations || 0
      };

    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Parses Taproot witness data
   */
  parseTaprootWitness(witness) {
    // Key-path spend: single signature
    if (witness.length === 1) {
      return {
        spendType: 'key_path',
        signature: Buffer.from(witness[0], 'hex')
      };
    }

    // Script-path spend: [...inputs, script, control_block]
    const controlBlock = Buffer.from(witness[witness.length - 1], 'hex');
    const leafScript = Buffer.from(witness[witness.length - 2], 'hex');
    const scriptInputs = witness.slice(0, -2).map(w => Buffer.from(w, 'hex'));

    return {
      spendType: 'script_path',
      controlBlock,
      leafScript,
      scriptInputs
    };
  }

  /**
   * Reconstructs Taproot output key from leaf script and control block
   * 
   * From spec:
   * "Recompute leaf hash → merkle root → tweaked key"
   */
  reconstructTaprootKey(leafScript, controlBlock) {
    // 1. Parse control block
    const leafVersion = controlBlock[0] & 0xfe;
    const outputKeyParity = controlBlock[0] & 0x01;
    const internalKey = controlBlock.slice(1, 33);
    
    // 2. Extract merkle proof
    const merkleProof = [];
    for (let i = 33; i < controlBlock.length; i += 32) {
      merkleProof.push(controlBlock.slice(i, i + 32));
    }

    // 3. Compute tapleaf hash
    const leafHash = crypto.createHash('sha256')
      .update(Buffer.concat([
        Buffer.from([leafVersion]),
        this.compactSize(leafScript.length),
        leafScript
      ]))
      .digest();

    // 4. Compute merkle root from leaf and proof
    let merkleRoot = leafHash;
    for (const sibling of merkleProof) {
      // Sort hashes for deterministic ordering
      const [left, right] = Buffer.compare(merkleRoot, sibling) < 0
        ? [merkleRoot, sibling]
        : [sibling, merkleRoot];
      
      merkleRoot = crypto.createHash('sha256')
        .update(Buffer.concat([left, right]))
        .digest();
    }

    // 5. Compute taproot output key: Q = P + H(P || root)G
    const tweak = crypto.createHash('sha256')
      .update(Buffer.concat([
        Buffer.from('TapTweak', 'utf8'),
        internalKey,
        merkleRoot
      ]))
      .digest();

    // In production, use secp256k1 library:
    // const taprootOutputKey = secp256k1.publicKeyTweakAdd(internalKey, tweak);
    
    // Placeholder for now
    const taprootOutputKey = internalKey.toString('hex');

    return {
      leafHash: leafHash.toString('hex'),
      merkleRoot: merkleRoot.toString('hex'),
      internalKey: internalKey.toString('hex'),
      taprootOutputKey
    };
  }

  /**
   * Bitcoin compact size encoding
   */
  compactSize(n) {
    if (n < 0xfd) return Buffer.from([n]);
    if (n <= 0xffff) return Buffer.concat([Buffer.from([0xfd]), Buffer.allocUnsafe(2).writeUInt16LE(n)]);
    if (n <= 0xffffffff) return Buffer.concat([Buffer.from([0xfe]), Buffer.allocUnsafe(4).writeUInt32LE(n)]);
    throw new Error('Size too large');
  }

  /**
   * Checks if a leaf script is a user-exit leaf
   */
  isUserExitLeaf(leafScript, template) {
    // Find "user-exit" role in template
    const exitLeafIndex = template.leafRoles.indexOf('user-exit');
    
    if (exitLeafIndex === -1) {
      return false;
    }

    // Get expected exit leaf script
    const expectedScript = template.leafScripts[exitLeafIndex];
    
    // Compare scripts
    // In production, you might want fuzzy matching for public key placeholders
    return leafScript.toString('hex') === Buffer.from(expectedScript, 'hex').toString('hex');
  }

  /**
   * Extracts the value released to the user
   */
  getReleasedValue(spendingTx, spendingInput) {
    // Sum all outputs (simplified - might want to filter by address)
    return spendingTx.vout.reduce((sum, out) => sum + Math.floor(out.value * 1e8), 0);
  }
}

/**
 * Main Ark-TradeLayer Bridge
 */
class ArkTradeLayerBridge {
  constructor() {
    this.templateRegistry = new ArkTemplateRegistry();
    this.depositRecognizer = new ArkDepositRecognizer(this.templateRegistry);
    this.exitRecognizer = new ArkExitRecognizer(this.templateRegistry);
  }

  /**
   * Registers a template (governance action)
   */
  registerTemplate(template, aspId) {
    return this.templateRegistry.registerTemplate(template, aspId);
  }

  /**
   * Validates a mint request
   */
  async validateMint(params) {
    const { templateId, aspId, depositTxid, depositVout, valueSats } = params;

    // 1. Verify template is in allowlist
    if (!this.templateRegistry.isAllowed(templateId, aspId)) {
      return {
        valid: false,
        reason: 'Template not in allowlist'
      };
    }

    // 2. Validate deposit
    const depositValidation = await this.depositRecognizer.validateDeposit(
      depositTxid,
      depositVout,
      valueSats
    );

    if (!depositValidation.valid) {
      return depositValidation;
    }

    // 3. Verify deposit matches claimed template
    if (depositValidation.commitment.templateId !== templateId ||
        depositValidation.commitment.aspId !== aspId) {
      return {
        valid: false,
        reason: 'Deposit template mismatch'
      };
    }

    return {
      valid: true,
      commitment: depositValidation.commitment,
      amountSats: depositValidation.amountSats
    };
  }

  /**
   * Validates a burn/redeem request
   */
  async validateBurn(params) {
    const { templateId, aspId, depositTxid, depositVout, redeemTxid } = params;

    // 1. Verify template is in allowlist
    if (!this.templateRegistry.isAllowed(templateId, aspId)) {
      return {
        valid: false,
        reason: 'Template not in allowlist'
      };
    }

    // 2. Validate exit spend
    const exitValidation = await this.exitRecognizer.validateExit(
      redeemTxid,
      depositTxid,
      depositVout
    );

    if (!exitValidation.valid) {
      return exitValidation;
    }

    // 3. Verify exit matches claimed template
    if (exitValidation.templateId !== templateId ||
        exitValidation.aspId !== aspId) {
      return {
        valid: false,
        reason: 'Exit template mismatch'
      };
    }

    return {
      valid: true,
      releasedValue: exitValidation.releasedValue,
      leafScript: exitValidation.leafScript
    };
  }
}

module.exports = {
  ArkTemplateRegistry,
  ArkDepositRecognizer,
  ArkExitRecognizer,
  ArkTradeLayerBridge
};
