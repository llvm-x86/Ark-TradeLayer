/**
 * Database Schemas
 * 
 * Mongoose schemas for persistent storage of loan contracts,
 * oracle announcements, and attestations.
 */

import { Schema, model, Document } from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";

/**
 * Event announcement schema
 * 
 * Stores pre-commitments to oracle events with R-values.
 */
export interface IEventAnnouncementDoc extends Document {
  /** Unique event identifier */
  eventId: string;
  /** SHA256 hash of announcement for quick lookup */
  announcementHash: string;
  /** Hex-encoded announcement message */
  announcementData: string;
  /** Oracle's public key */
  oraclePublicKey: string;
  /** Event type: numeric, binary, enum */
  eventType: "numeric" | "binary" | "enum";
  /** Event maturity timestamp */
  maturityTime: number;
  /** R-value nonce commitments */
  nonceCommitments: Array<{ index: number; rValue: string }>;
  /** Associated attestation (populated after event matures) */
  attestationId?: string;
  /** Creation timestamp */
  createdAt: Date;
  /** Update timestamp */
  updatedAt: Date;
}

const EventAnnouncementSchema = new Schema<IEventAnnouncementDoc>(
  {
    eventId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    announcementHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    announcementData: {
      type: String,
      required: true,
    },
    oraclePublicKey: {
      type: String,
      required: true,
      index: true,
    },
    eventType: {
      type: String,
      required: true,
      enum: ["numeric", "binary", "enum"],
      index: true,
    },
    maturityTime: {
      type: Number,
      required: true,
      index: true,
    },
    nonceCommitments: [
      {
        index: Number,
        rValue: String,
      },
    ],
    attestationId: {
      type: String,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index for querying mature events
EventAnnouncementSchema.index({ maturityTime: 1, attestationId: 1 });

// Unique index on all nonce commitments to prevent reuse
EventAnnouncementSchema.index(
  { "nonceCommitments.rValue": 1 },
  { unique: true, sparse: true }
);

EventAnnouncementSchema.plugin(mongoosePaginate);

export const EventAnnouncementModel = model<IEventAnnouncementDoc>(
  "EventAnnouncement",
  EventAnnouncementSchema
);

/**
 * Attestation record schema
 * 
 * Stores signed attestations to event outcomes.
 */
export interface IAttestationRecordDoc extends Document {
  /** Unique attestation identifier */
  attestationId: string;
  /** Associated event ID */
  eventId: string;
  /** Oracle's public key */
  oraclePublicKey: string;
  /** Attested outcomes */
  outcomes: string[];
  /** Schnorr signatures for each outcome */
  signatures: string[];
  /** Hex-encoded full attestation message */
  attestationData: string;
  /** Attestation timestamp */
  attestationTime: number;
  /** Verification status */
  verified: boolean;
  /** Creation timestamp */
  createdAt: Date;
}

const AttestationRecordSchema = new Schema<IAttestationRecordDoc>(
  {
    attestationId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    eventId: {
      type: String,
      required: true,
      index: true,
    },
    oraclePublicKey: {
      type: String,
      required: true,
      index: true,
    },
    outcomes: [String],
    signatures: [String],
    attestationData: {
      type: String,
      required: true,
    },
    attestationTime: {
      type: Number,
      required: true,
      index: true,
    },
    verified: {
      type: Boolean,
      required: true,
      default: false,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

AttestationRecordSchema.plugin(mongoosePaginate);

export const AttestationRecordModel = model<IAttestationRecordDoc>(
  "AttestationRecord",
  AttestationRecordSchema
);

/**
 * Loan contract schema
 * 
 * Stores VTXO-based loan contract state.
 */
export interface ILoanContractDoc extends Document {
  /** Unique loan identifier */
  loanId: string;
  /** Contract type */
  contractType: "collateralized" | "unsecured" | "custom";
  /** Lender's public key */
  lenderPubkey: string;
  /** Borrower's public key */
  borrowerPubkey: string;
  /** Server (ASP) public key */
  serverPubkey: string;
  /** Oracle public key */
  oraclePubkey: string;
  /** Loan terms (hashed for privacy) */
  termsHash: string;
  /** Principal amount (satoshis) */
  principalAmount: number;
  /** Collateral amount (satoshis, if applicable) */
  collateralAmount?: number;
  /** Interest amount (satoshis) */
  interestAmount: number;
  /** Loan maturity timestamp */
  maturityTime: number;
  /** Repayment deadline timestamp */
  repaymentDeadline: number;
  /** Associated oracle event IDs */
  oracleEvents: {
    repaymentEventId?: string;
    priceEventId?: string;
    otherEventIds?: string[];
  };
  /** VTXO details */
  vtxo: {
    /** Funding transaction ID */
    fundingTxid?: string;
    /** Funding output index */
    fundingVout?: number;
    /** VTXO locking script */
    lockingScript: string;
    /** Exit delay (blocks) */
    exitDelay: number;
  };
  /** Current contract state */
  status:
    | "pending"
    | "active"
    | "repaid"
    | "defaulted"
    | "liquidated"
    | "disputed";
  /** Settlement transaction (if settled) */
  settlementTxid?: string;
  /** Settlement outcome */
  settlementOutcome?: string;
  /** Creation timestamp */
  createdAt: Date;
  /** Update timestamp */
  updatedAt: Date;
}

const LoanContractSchema = new Schema<ILoanContractDoc>(
  {
    loanId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    contractType: {
      type: String,
      required: true,
      enum: ["collateralized", "unsecured", "custom"],
      index: true,
    },
    lenderPubkey: {
      type: String,
      required: true,
      index: true,
    },
    borrowerPubkey: {
      type: String,
      required: true,
      index: true,
    },
    serverPubkey: {
      type: String,
      required: true,
    },
    oraclePubkey: {
      type: String,
      required: true,
    },
    termsHash: {
      type: String,
      required: true,
    },
    principalAmount: {
      type: Number,
      required: true,
    },
    collateralAmount: {
      type: Number,
    },
    interestAmount: {
      type: Number,
      required: true,
    },
    maturityTime: {
      type: Number,
      required: true,
      index: true,
    },
    repaymentDeadline: {
      type: Number,
      required: true,
      index: true,
    },
    oracleEvents: {
      repaymentEventId: String,
      priceEventId: String,
      otherEventIds: [String],
    },
    vtxo: {
      fundingTxid: String,
      fundingVout: Number,
      lockingScript: {
        type: String,
        required: true,
      },
      exitDelay: {
        type: Number,
        required: true,
      },
    },
    status: {
      type: String,
      required: true,
      enum: ["pending", "active", "repaid", "defaulted", "liquidated", "disputed"],
      index: true,
      default: "pending",
    },
    settlementTxid: String,
    settlementOutcome: String,
  },
  {
    timestamps: true,
  }
);

// Compound indexes for common queries
LoanContractSchema.index({ status: 1, maturityTime: 1 });
LoanContractSchema.index({ status: 1, repaymentDeadline: 1 });
LoanContractSchema.index({ lenderPubkey: 1, status: 1 });
LoanContractSchema.index({ borrowerPubkey: 1, status: 1 });

LoanContractSchema.plugin(mongoosePaginate);

export const LoanContractModel = model<ILoanContractDoc>(
  "LoanContract",
  LoanContractSchema
);

/**
 * Witness check log schema
 * 
 * Logs all witness condition checks for audit trail.
 */
export interface IWitnessCheckLogDoc extends Document {
  /** Associated event ID */
  eventId: string;
  /** Witness type */
  witnessType: "payment" | "threshold" | "time" | "composite";
  /** Whether condition was met */
  conditionMet: boolean;
  /** Witness data (JSON) */
  witnessData: any;
  /** Data source */
  source: string;
  /** Confidence score */
  confidence?: number;
  /** Check timestamp */
  checkedAt: Date;
}

const WitnessCheckLogSchema = new Schema<IWitnessCheckLogDoc>(
  {
    eventId: {
      type: String,
      required: true,
      index: true,
    },
    witnessType: {
      type: String,
      required: true,
      enum: ["payment", "threshold", "time", "composite"],
      index: true,
    },
    conditionMet: {
      type: Boolean,
      required: true,
      index: true,
    },
    witnessData: {
      type: Schema.Types.Mixed,
      required: true,
    },
    source: {
      type: String,
      required: true,
    },
    confidence: Number,
    checkedAt: {
      type: Date,
      required: true,
      index: true,
    },
  },
  {
    timestamps: false,
  }
);

// Compound index for querying recent checks
WitnessCheckLogSchema.index({ eventId: 1, checkedAt: -1 });

export const WitnessCheckLogModel = model<IWitnessCheckLogDoc>(
  "WitnessCheckLog",
  WitnessCheckLogSchema
);
