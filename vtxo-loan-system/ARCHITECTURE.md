# VTXO Loan Contract System - Architecture

## Overview

This system implements Bitcoin-native loan contracts using three key technologies:
- **VTXOs (Virtual Transaction Outputs)** from Ark protocol for efficient off-chain execution
- **DLCs (Discreet Log Contracts)** for conditional settlements based on oracle data
- **Adaptor signatures** for privacy-preserving conditional payments

## Core Components

### 1. Attestation Service (`/attestation`)
Provides cryptographic proofs for external events that influence loan conditions.

**Key Modules:**
- `AttestationEngine` - Core signing and verification logic
- `EventWitness` - Tracks and validates external events
- `SignatureProducer` - Generates Schnorr signatures with nonce management
- `WitnessScheduler` - Coordinates periodic attestation creation

**Oracle Types:**
- **Numeric Oracles**: Price feeds, threshold monitoring
- **Binary Oracles**: Payment confirmation, event occurrence
- **Composite Oracles**: Multi-condition attestations

### 2. Contract Templates (`/contracts`)
Arkade Script templates for various loan contract types.

**Templates:**
- `CollateralizedLoan.ark` - Loan with collateral and liquidation
- `UnsecuredLoan.ark` - Trust-based loan with reputation oracle
- `RepaymentEscrow.ark` - Multi-stage payment verification
- `DefaultHandler.ark` - Liquidation and recovery logic

### 3. VTXO Management (`/vtxo`)
Handles Virtual Transaction Output lifecycle and covenant enforcement.

**Key Modules:**
- `VtxoFactory` - Creates VTXO structures with proper locking scripts
- `CovenantEngine` - Enforces state transitions and spending conditions
- `ExitPathBuilder` - Constructs unilateral exit paths with timelocks
- `CooperativePath` - Manages server-assisted instant settlements

### 4. DLC Integration (`/dlc`)
Bridges oracle attestations with Bitcoin script execution.

**Key Modules:**
- `AdaptorSigManager` - Creates and validates adaptor signatures
- `OutcomeMapper` - Maps oracle attestations to payout curves
- `CetBuilder` - Constructs Contract Execution Transactions
- `SettlementCoordinator` - Manages multi-party DLC settlements

### 5. Key Management (`/keys`)
Secure key derivation and signature production.

**Modes:**
- **Development**: In-memory key derivation from seed
- **Production**: Cloud HSM integration (GCP KMS, AWS CloudHSM)
- **Simulation**: Deterministic keys for testing

### 6. External Data (`/external`)
Integrations for monitoring real-world events.

**Sources:**
- **Blockchain Monitors**: Ethereum payment tracking, Bitcoin confirmations
- **Price Feeds**: Multiple exchange aggregation with outlier detection
- **Identity Oracles**: KYC verification, credit scores

### 7. Storage Layer (`/storage`)
Persistent state management.

**Collections:**
- `event_announcements` - Oracle event pre-commitments
- `attestation_records` - Signed attestations with nonce proofs
- `loan_contracts` - Active and historical loan state
- `vtxo_registry` - VTXO tracking and covenant state

## Data Flow

### Loan Origination Flow
```
1. Borrower creates loan request
   ↓
2. System generates oracle event announcements:
   - Payment confirmation oracle (Binary)
   - Collateral value oracle (Numeric)
   - Expiration oracle (Time-based)
   ↓
3. DLC adapter constructs payout structure:
   - Full repayment: Borrower gets collateral back
   - Partial payment: Pro-rata settlement
   - Default: Lender receives collateral
   ↓
4. VTXO factory creates Virtual TXO with:
   - Cooperative path (instant settlement with server)
   - Unilateral exit path (timelock + redemption)
   ↓
5. Parties sign and commit
```

### Attestation Flow
```
1. Scheduler triggers attestation check
   ↓
2. EventWitness queries external data sources
   ↓
3. If conditions met, SignatureProducer creates attestation:
   - Derives deterministic nonce
   - Signs outcome message
   - Publishes attestation
   ↓
4. DLC participants use attestation to:
   - Calculate adaptor secret
   - Unlock conditional payments
   - Execute settlement path
```

### Settlement Flow
```
1. Oracle publishes attestation
   ↓
2. SettlementCoordinator determines winning outcome
   ↓
3. Winner constructs CET (Contract Execution Transaction)
   ↓
4. If cooperative:
   - Both parties + server sign
   - Immediate finality
   ↓
5. If unilateral:
   - Winner waits for timelock
   - Broadcasts unilateral exit
   - Settles on-chain
```

## Security Model

### Trust Assumptions
- **Oracle Honesty**: Oracle must attest to truthful outcomes
- **Server Availability**: For cooperative paths, server must be online
- **Timelock Safety**: Unilateral exits require sufficient timelock buffer

### Attack Mitigations
- **Nonce Reuse Prevention**: Deterministic nonce derivation with event ID
- **Double-Spend Protection**: Taproot output commitment verification
- **Collusion Resistance**: Multi-oracle aggregation for critical events
- **Censorship Resistance**: Unilateral exit paths guarantee settlement

## Deployment Topologies

### Development
- Single-node oracle
- Local Bitcoin regtest
- In-memory keys
- MongoDB local instance

### Staging
- Multi-oracle federation
- Bitcoin testnet
- Cloud secret storage
- Redis job queue

### Production
- Decentralized oracle network
- Bitcoin mainnet
- Hardware security modules
- Distributed storage + caching

## Extension Points

### Custom Oracle Types
Implement `EventWitness` interface:
```typescript
interface EventWitness<T> {
  checkCondition(): Promise<WitnessResult<T>>;
  extractOutcome(result: WitnessResult<T>): string;
  validateSource(source: DataSource): boolean;
}
```

### Custom Contract Templates
Write Arkade Script with required interface:
```
contract LoanTemplate(
  pubkey lender,
  pubkey borrower,
  pubkey server,
  bytes32 loanTermsHash
) {
  function repay(signature borrowerSig, bytes oracleAttestation) { ... }
  function liquidate(signature lenderSig, bytes oracleAttestation) { ... }
  function exit(signature partySig) { ... }
}
```

### Custom Settlement Logic
Implement `SettlementStrategy`:
```typescript
interface SettlementStrategy {
  calculatePayouts(
    loanTerms: LoanTerms,
    attestation: Attestation
  ): PayoutMap;
  buildExecutionTx(payouts: PayoutMap): Transaction;
}
```

## Performance Characteristics

- **Attestation Latency**: < 5 seconds from condition trigger
- **Oracle Throughput**: 1000+ attestations/minute
- **VTXO Creation**: < 100ms per contract
- **Cooperative Settlement**: < 1 second finality
- **Unilateral Settlement**: Timelock period (e.g., 1 week)

## Monitoring & Observability

### Key Metrics
- Attestation creation rate
- Oracle data source latency
- Settlement success rate (cooperative vs unilateral)
- Key derivation performance
- Database query performance

### Alerting
- Oracle data source unavailability
- Attestation signature failures
- Unusual settlement patterns
- Key management errors
- Database connection failures

## Testing Strategy

### Unit Tests
- Cryptographic primitives (signature, verification, nonce derivation)
- Oracle logic (condition checking, outcome extraction)
- VTXO construction (covenant validation, script generation)

### Integration Tests
- End-to-end loan flows (origination → repayment → settlement)
- Oracle coordination (multiple data sources)
- Key management (different backends)

### Regression Tests
- Known attack vectors
- Edge cases in payout calculations
- Timelock boundary conditions

### Simulation Tests
- Large-scale oracle network
- Byzantine oracle behavior
- Network partition scenarios
