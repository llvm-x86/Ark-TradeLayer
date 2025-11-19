# Ark-TradeLayer Integration: Handshake Spec Approach

## Executive Summary

The handshake spec provides a **significantly cleaner architecture** than recursive VTXO tree parsing. Key improvements:

### ✅ What Makes This Better

1. **Template Allowlist** - Governance-controlled set of vetted templates prevents trap scripts
2. **Simple Recognition** - Just match `taprootOutputKey` to known templates (O(1) lookup)
3. **No Tree Traversal** - Don't need to recursively parse VTXO branches
4. **Canonical Identity** - SHA256-based `templateId` ensures deterministic verification
5. **Clear Separation** - Handshake (trust/auth) vs Protocol (cryptographic verification)

### 🎯 Core Insight

**You only need to recognize TWO events:**

1. **Deposit** (Mint): User creates UTXO with known `taprootOutputKey`
2. **Exit** (Burn): User spends UTXO via script-path revealing "user-exit" leaf

Everything else (rounds, VTXO tree structure, checkpoint txs) happens **off-chain** in Ark's virtual mempool.

---

## Architecture Comparison

### Old Approach (Recursive Tree Parsing)

```
Problems:
├── Need to parse entire VTXO tree structure
├── Track round rollovers in real-time
├── Recursively follow branch transactions
├── Handle checkpoint transactions
├── Monitor forfeit transactions
└── Complex state management

Code: ~1500 lines
Complexity: O(tree_depth * tree_breadth)
```

### New Approach (Handshake Spec)

```
Solution:
├── Allowlist of templateIds (governance)
├── Index taprootOutputKey → (templateId, aspId)
├── Deposit recognition: O(1) lookup
├── Exit validation: Parse one script-path spend
└── Simple state: deposit UTXO → token minted

Code: ~500 lines
Complexity: O(1) for deposits, O(merkle_depth) for exits
```

---

## Implementation Guide

### Step 1: Register Templates

Templates must be registered in TradeLayer (governance action):

```javascript
const { ArkTradeLayerBridge } = require('./arkTradeLayerHandshake.js');

const bridge = new ArkTradeLayerBridge();

// Define template (from ASP)
const arkTemplate = {
  version: 1,
  network: 'bitcoin-mainnet',
  internalKey: '02...',
  leafScripts: [
    '20<user_pk>ac20<server_pk>ac',  // cooperative
    '20<user_pk>ac02f003b2',          // user exit after CSV
    '20<server_pk>ac02d007b2'         // asp forfeit
  ],
  leafVersions: [0xc0, 0xc0, 0xc0],
  leafRoles: ['batch-settle', 'user-exit', 'asp-forfeit'],
  timeouts: {
    userExitCsv: 1008,
    aspForfeitCsv: 2000
  },
  semantics: {
    batchSettle: 'Cooperative spend',
    userExit: 'Unilateral exit after timeout',
    aspForfeit: 'Penalty for misbehavior'
  },
  merkleRoot: '...',
  taprootOutputKey: '...'
};

// Register with ASP identity
const templateId = bridge.registerTemplate(
  arkTemplate,
  'ark.example.com' // aspId
);

console.log('Registered template:', templateId);
```

### Step 2: Validate Deposits (Mints)

When user wants to mint wrapped ARK-BTC:

```javascript
// User deposits BTC to Ark
// Gets back: depositTxid, depositVout, userVtxoId

// User creates TradeLayer transaction: ARK_WRAP_MINT
const mintParams = {
  type: 'ark-vtxo',
  templateId: '0xabcd...',
  aspId: 'ark.example.com',
  depositTxid: 'abc123...',
  depositVout: 0,
  valueSats: 100000000, // 1 BTC
  ticker: 'aARK',
  initialAmount: 100000000
};

// TradeLayer validates
const validation = await bridge.validateMint(mintParams);

if (validation.valid) {
  // Mint tokens to user
  await mintTokens(user, mintParams.valueSats);
}
```

**What gets checked:**

```javascript
validateMint() {
  // 1. templateId in ALLOWED_TEMPLATES? ✓
  // 2. aspId matches templateId? ✓
  // 3. depositTxid:vout exists on chain? ✓
  // 4. depositTxid:vout has 6+ confirmations? ✓
  // 5. Output scriptPubKey is Taproot? ✓
  // 6. taprootOutputKey matches template? ✓
  // 7. Value matches? ✓
  // 8. UTXO unspent? ✓
}
```

### Step 3: Validate Exits (Burns)

When user wants to redeem:

```javascript
// User initiates exit from Ark
// Gets back: redeemTxid (spending the deposit UTXO)

// User creates TradeLayer transaction: REDEEM
const burnParams = {
  propertyId: 123,
  amount: 100000000,
  redeemTxid: 'def456...'
};

// TradeLayer validates
const validation = await bridge.validateBurn({
  templateId: tokenData.templateId,
  aspId: tokenData.aspId,
  depositTxid: tokenData.depositTxid,
  depositVout: tokenData.depositVout,
  redeemTxid: burnParams.redeemTxid
});

if (validation.valid) {
  // Burn tokens
  await burnTokens(user, burnParams.amount);
}
```

**What gets checked:**

```javascript
validateBurn() {
  // 1. redeemTxid exists on chain? ✓
  // 2. redeemTxid spends depositTxid:vout? ✓
  // 3. Spend is script-path (not key-path)? ✓
  // 4. Extract leaf script from witness ✓
  // 5. Recompute merkleRoot from leaf + control block ✓
  // 6. Reconstruct taprootOutputKey ✓
  // 7. taprootOutputKey matches template? ✓
  // 8. Leaf script is "user-exit" role? ✓
  // 9. Value released to user? ✓
}
```

---

## Protocol-Level Parsing

### For Deposits

```javascript
// Simple Taproot output recognition
function isArkCommitmentUtxo(utxo, templates) {
  // 1. Decode scriptPubKey
  const { version, program } = decodeSegwit(utxo.scriptPubKey);
  
  if (version !== 1 || program.length !== 32) {
    return null; // Not Taproot
  }

  const taprootOutputKey = program.toString('hex');

  // 2. O(1) lookup in template index
  const match = templates.findByOutputKey(taprootOutputKey);
  
  return match; // { templateId, aspId } or null
}
```

### For Exits

```javascript
// Parse script-path spend
function validateExitSpend(spendingTx, depositUtxo, template) {
  // 1. Find input spending deposit
  const input = spendingTx.vin.find(
    vin => vin.txid === depositUtxo.txid && vin.vout === depositUtxo.vout
  );

  // 2. Extract witness data
  const witness = input.txinwitness;
  const leafScript = witness[witness.length - 2];
  const controlBlock = witness[witness.length - 1];

  // 3. Recompute merkle root
  const leafHash = sha256(leafVersion || leafScript);
  const merkleRoot = computeMerkleRoot(leafHash, controlBlock.merkleProof);

  // 4. Recompute taproot key
  const tweak = sha256('TapTweak' || internalKey || merkleRoot);
  const taprootKey = internalKey + tweak * G;

  // 5. Verify it matches template
  return taprootKey === template.taprootOutputKey &&
         leafScript === template.leafScripts[exitLeafIndex];
}
```

---

## Template Canonicity

### Computing templateId

```javascript
function computeTemplateId(template) {
  const canonical = {
    version: template.version,
    network: template.network,
    internalKey: template.internalKey,
    merkleRoot: template.merkleRoot,
    leafScripts: template.leafScripts.sort(), // deterministic order
    leafVersions: template.leafVersions,
    leafRoles: template.leafRoles,
    timeouts: canonicalJSON(template.timeouts),
    semantics: canonicalJSON(template.semantics)
  };

  const serialized = Buffer.concat([
    Buffer.from('TL_ARK_TEMPLATE_V1'),
    Buffer.from(canonical.network),
    Buffer.from(canonical.internalKey, 'hex'),
    Buffer.from(canonical.merkleRoot, 'hex'),
    Buffer.from(JSON.stringify({
      leafScripts: canonical.leafScripts,
      leafVersions: canonical.leafVersions,
      leafRoles: canonical.leafRoles,
      timeouts: canonical.timeouts,
      semantics: canonical.semantics
    }))
  ]);

  return sha256(serialized).toString('hex');
}
```

### Canonical JSON

```javascript
function canonicalJSON(obj) {
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
```

---

## Integration with TradeLayer

### Modify validity.js

```javascript
const { DLCVTXOValidation } = require('./dlcVtxoValidationV2.js');

// In validateTokenIssue:
if (params.type === 'ark-vtxo' || params.type === 'dlc-vtxo') {
  return await DLCVTXOValidation.validateDLCVTXOMint(sender, params, txid);
}

// Add new validation for redeems:
validateArkRedemption: async (sender, params, txid) => {
  return await DLCVTXOValidation.validateDLCVTXOBurn(sender, params, txid);
}
```

### Modify logic.js

```javascript
const DLCVTXOLogic = require('./dlcVtxoLogic.js');

// In tokenIssue:
if (params.type === 'ark-vtxo') {
  return await DLCVTXOLogic.mintDLCVTXOToken(
    sender,
    initialAmount,
    ticker,
    url,
    whitelistId,
    backupAddress,
    block,
    params.templateId,
    params.aspId,
    params.depositTxid,
    params.depositVout,
    params.taprootOutputKey
  );
}

// In redeemManagedToken:
if (propertyData.type === 'ark-vtxo') {
  return await DLCVTXOLogic.burnDLCVTXOToken(
    senderAddress,
    propertyId,
    amount,
    params.redeemTxid,
    block
  );
}
```

### Database Schema

```sql
-- Add to properties table
ALTER TABLE properties ADD COLUMN template_id VARCHAR(64);
ALTER TABLE properties ADD COLUMN asp_id VARCHAR(255);
ALTER TABLE properties ADD COLUMN deposit_txid VARCHAR(64);
ALTER TABLE properties ADD COLUMN deposit_vout INT;
ALTER TABLE properties ADD COLUMN taproot_output_key VARCHAR(64);
ALTER TABLE properties ADD COLUMN redeem_txid VARCHAR(64);

CREATE INDEX idx_deposit_utxo ON properties(deposit_txid, deposit_vout);
CREATE INDEX idx_template ON properties(template_id, asp_id);
```

---

## Governance: Template Allowlist

### Adding Templates

Templates should be added via governance transaction:

```javascript
// TX Type: ADD_ARK_TEMPLATE (new type)
{
  templateId: '0xabcd...',
  aspId: 'ark.example.com',
  templateData: { /* full ArkTemplate object */ },
  proposer: 'tl1...',
  votingPeriod: 1008 // blocks
}
```

### Removing Templates

```javascript
// TX Type: REMOVE_ARK_TEMPLATE
{
  templateId: '0xabcd...',
  aspId: 'ark.example.com',
  reason: 'ASP compromised',
  proposer: 'tl1...'
}
```

---

## Security Considerations

### Protocol-Level

✅ **Solved by Handshake Spec:**
- Template canonicity (SHA256 checksum)
- Trap script prevention (allowlist)
- UTXO validity (on-chain verification)
- Exit validation (script-path parsing)

### App-Level

⚠️ **Still Need:**
- ASP reputation tracking
- UI warnings about ASP identity
- Monitoring for ASP misbehavior
- User education about Ark trust model

### Attack Vectors

| Attack | Mitigation |
|--------|-----------|
| Fake ASP | Check `aspId` against known identities |
| Trap script | Template allowlist (governance vetted) |
| Double-mint | Track deposit UTXOs in registry |
| Exit griefing | Verify script-path reveals correct leaf |
| ASP censorship | User can always exit via CSV timeout |

---

## Testing

### Unit Tests

```javascript
describe('Ark-TradeLayer Handshake', () => {
  it('should compute canonical templateId', () => {
    const template = { /* ... */ };
    const id1 = computeTemplateId(template);
    const id2 = computeTemplateId(template);
    assert(id1 === id2);
  });

  it('should recognize Ark deposit UTXOs', () => {
    const utxo = {
      scriptPubKey: '51200279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817',
      value: 1.0
    };
    const match = isArkCommitmentUtxo(utxo, templates);
    assert(match.templateId === expectedId);
  });

  it('should validate exit spends', () => {
    const validation = validateExitSpend(redeemTx, depositUtxo, template);
    assert(validation.valid === true);
  });
});
```

### Integration Tests

```javascript
describe('End-to-End Flow', () => {
  it('should mint and burn wrapped ARK-BTC', async () => {
    // 1. Register template
    const templateId = await registerTemplate(template, aspId);
    
    // 2. User deposits to Ark
    const deposit = await depositToArk(1.0);
    
    // 3. Mint TradeLayer tokens
    const mint = await mintArkToken(deposit);
    assert(mint.success);
    
    // 4. User exits Ark
    const exit = await exitFromArk(deposit);
    
    // 5. Burn TradeLayer tokens
    const burn = await burnArkToken(exit);
    assert(burn.success);
  });
});
```

---

## Comparison: What You DON'T Need

### ❌ Old Approach Required:

- ✗ Parse commitment transaction structure
- ✗ Extract connector UTXO
- ✗ Recursively build VTXO tree
- ✗ Track round rollovers
- ✗ Monitor forfeit transactions
- ✗ Monitor checkpoint transactions
- ✗ Parse VTXO witness data for every node
- ✗ Maintain VTXO state machine

### ✅ New Approach Only Needs:

- ✓ Template allowlist (governance)
- ✓ Deposit recognition (O(1) lookup)
- ✓ Exit validation (parse one spend)
- ✓ Simple UTXO registry

---

## Production Checklist

- [ ] Implement proper secp256k1 library for Taproot key computation
- [ ] Add template governance transactions
- [ ] Create template vetting process
- [ ] Build ASP identity verification
- [ ] Add monitoring for exit spends
- [ ] Create UI for template status
- [ ] Audit template canonicity logic
- [ ] Test on Ark testnet
- [ ] Document user flow
- [ ] Deploy to mainnet

---

## Conclusion

The handshake spec approach is **dramatically simpler** than recursive tree parsing:

- **500 lines** instead of 1500+
- **O(1) complexity** instead of O(tree_size)
- **2 critical events** (deposit, exit) instead of tracking full tree
- **Allowlist governance** prevents trap scripts
- **Canonical templateId** ensures deterministic verification

This is the **right architecture** for Ark-TradeLayer integration!
