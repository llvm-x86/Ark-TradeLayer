/**
 * System Configuration
 * 
 * Centralized configuration management for the VTXO loan system.
 */

import { BitcoinNetwork, BitcoinNetworks } from "bitcoin-networks";

/**
 * Supported Bitcoin networks
 */
export type NetworkType = "mainnet" | "testnet" | "regtest" | "signet";

/**
 * Oracle operating modes
 */
export type OracleMode = "development" | "staging" | "production";

/**
 * Key management configuration
 */
export interface KeyManagementConfig {
  /** Provider type */
  provider: "local" | "gcp" | "aws" | "mock";
  /** For local: mnemonic phrase */
  mnemonic?: string;
  /** For cloud: project/account ID */
  projectId?: string;
  /** For cloud: secret identifier */
  secretId?: string;
  /**
   * Explicit opt-in required to use the "local" key provider outside
   * development (set ALLOW_LOCAL_KEYS=1). Local mnemonics sitting in the
   * process environment are not acceptable key custody for real funds.
   */
  allowLocalKeys?: boolean;
}

/**
 * Database configuration
 */
export interface DatabaseConfig {
  /** MongoDB connection URI */
  uri: string;
  /** Database name */
  database: string;
  /** Connection pool size */
  poolSize?: number;
}

/**
 * Redis configuration for job queue
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
}

/**
 * External data source configuration
 */
export interface ExternalDataConfig {
  /** Price data sources */
  priceFeeds: {
    coinGeckoApiKey?: string;
    coinbaseApiKey?: string;
    enabled: string[]; // e.g., ["coingecko", "coinbase", "kraken"]
  };
  /** Blockchain data sources */
  blockchainClients: {
    /** Ethereum RPC configuration */
    ethereum?: {
      alchemyApiKey?: string;
      infuraApiKey?: string;
      networks: string[]; // e.g., ["mainnet", "sepolia"]
    };
    /** Bitcoin RPC configuration */
    bitcoin?: {
      rpcUrl: string;
      rpcUser?: string;
      rpcPassword?: string;
    };
  };
}

/**
 * API server configuration
 */
export interface ApiConfig {
  /** Public API port */
  publicPort: number;
  /** Internal admin API port */
  internalPort: number;
  /** API authentication key */
  authKey: string;
  /** CORS configuration */
  cors: {
    enabled: boolean;
    origins: string[];
  };
}

/**
 * Monitoring and alerting configuration
 */
export interface MonitoringConfig {
  /** Sentry DSN for error tracking */
  sentryDsn?: string;
  /** Slack webhook for alerts */
  slackWebhook?: string;
  /** Log level */
  logLevel: "debug" | "info" | "warn" | "error";
}

/**
 * Attestation scheduler configuration
 */
export interface SchedulerConfig {
  /** Price check interval (minutes) */
  priceCheckInterval: number;
  /** Payment check interval (minutes) */
  paymentCheckInterval: number;
  /** Announcement lookahead (weeks) */
  announcementLookahead: number;
}

/**
 * VTXO contract configuration
 */
export interface VtxoConfig {
  /** Default exit timelock (blocks) */
  defaultExitDelay: number;
  /** Server public key for cooperative paths */
  serverPublicKey: string;
  /** Minimum contract value (satoshis) */
  minContractValue: number;
}

/**
 * Main system configuration
 */
export interface SystemConfig {
  /** Bitcoin network */
  network: NetworkType;
  /** Oracle operating mode */
  mode: OracleMode;
  /** Key management */
  keys: KeyManagementConfig;
  /** Database */
  database: DatabaseConfig;
  /** Redis job queue */
  redis: RedisConfig;
  /** External data sources */
  externalData: ExternalDataConfig;
  /** API server */
  api: ApiConfig;
  /** Monitoring */
  monitoring: MonitoringConfig;
  /** Scheduler */
  scheduler: SchedulerConfig;
  /** VTXO contracts */
  vtxo: VtxoConfig;
}

/**
 * Insecure placeholder API key shipped in .env.example. Never acceptable
 * outside development.
 */
export const DEFAULT_API_AUTH_KEY = "dev-key-insecure";

/**
 * Loads configuration from environment variables
 */
export function loadConfigFromEnv(): SystemConfig {
  // Network configuration
  const networkType = (process.env.NETWORK || "regtest") as NetworkType;
  const mode = (process.env.ORACLE_MODE || "development") as OracleMode;

  // Key management
  const keyProvider = process.env.KEY_PROVIDER || "mock";
  const keys: KeyManagementConfig = {
    provider: keyProvider as any,
    mnemonic: process.env.MNEMONIC,
    projectId: process.env.CLOUD_PROJECT_ID,
    secretId: process.env.CLOUD_SECRET_ID || "oracle-mnemonic",
    allowLocalKeys: process.env["ALLOW_LOCAL_KEYS"] === "1",
  };

  // Database
  const database: DatabaseConfig = {
    uri: process.env.MONGODB_URI || "mongodb://localhost:27017",
    database: process.env.MONGODB_DATABASE || "vtxo-loans",
    poolSize: parseInt(process.env.MONGODB_POOL_SIZE || "10"),
  };

  // Redis
  const redis: RedisConfig = {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: parseInt(process.env.REDIS_PORT || "6379"),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || "0"),
  };

  // External data sources
  const externalData: ExternalDataConfig = {
    priceFeeds: {
      coinGeckoApiKey: process.env.COINGECKO_API_KEY,
      coinbaseApiKey: process.env.COINBASE_API_KEY,
      enabled: (process.env.PRICE_FEED_SOURCES || "coingecko,coinbase,kraken").split(","),
    },
    blockchainClients: {
      ethereum: process.env.ETHEREUM_ENABLED === "true" ? {
        alchemyApiKey: process.env.ALCHEMY_API_KEY,
        infuraApiKey: process.env.INFURA_API_KEY,
        networks: (process.env.ETH_NETWORKS || "mainnet,sepolia").split(","),
      } : undefined,
      bitcoin: process.env.BITCOIN_RPC_URL ? {
        rpcUrl: process.env.BITCOIN_RPC_URL,
        rpcUser: process.env.BITCOIN_RPC_USER,
        rpcPassword: process.env.BITCOIN_RPC_PASSWORD,
      } : undefined,
    },
  };

  // API server
  const api: ApiConfig = {
    publicPort: parseInt(process.env.PUBLIC_API_PORT || "3000"),
    internalPort: parseInt(process.env.INTERNAL_API_PORT || "3001"),
    authKey: process.env.API_AUTH_KEY || DEFAULT_API_AUTH_KEY,
    cors: {
      enabled: process.env.CORS_ENABLED !== "false",
      origins: (process.env.CORS_ORIGINS || "*").split(","),
    },
  };

  // Monitoring
  const monitoring: MonitoringConfig = {
    sentryDsn: process.env.SENTRY_DSN,
    slackWebhook: process.env.SLACK_WEBHOOK,
    logLevel: (process.env.LOG_LEVEL || "info") as any,
  };

  // Scheduler
  const scheduler: SchedulerConfig = {
    priceCheckInterval: parseInt(process.env.PRICE_CHECK_INTERVAL || "5"),
    paymentCheckInterval: parseInt(process.env.PAYMENT_CHECK_INTERVAL || "2"),
    announcementLookahead: parseInt(process.env.ANNOUNCEMENT_LOOKAHEAD || "13"),
  };

  // VTXO
  const vtxo: VtxoConfig = {
    defaultExitDelay: parseInt(process.env.VTXO_EXIT_DELAY || "1008"),
    serverPublicKey: process.env.VTXO_SERVER_PUBKEY || "",
    minContractValue: parseInt(process.env.MIN_CONTRACT_VALUE || "10000"),
  };

  return {
    network: networkType,
    mode,
    keys,
    database,
    redis,
    externalData,
    api,
    monitoring,
    scheduler,
    vtxo,
  };
}

/**
 * Converts network type to BitcoinNetwork object
 */
export function getBitcoinNetwork(networkType: NetworkType): BitcoinNetwork {
  switch (networkType) {
    case "mainnet":
      return BitcoinNetworks.bitcoin;
    case "testnet":
      return BitcoinNetworks.bitcoin_testnet;
    case "regtest":
      return BitcoinNetworks.bitcoin_regtest;
    case "signet":
      return BitcoinNetworks.bitcoin_testnet; // Use testnet params for signet
    default:
      throw new Error(`Unknown network type: ${networkType}`);
  }
}

/**
 * Validates configuration
 *
 * Security-critical misconfigurations (insecure key custody, default
 * credentials outside development) are fail-closed: they THROW here instead
 * of being returned as soft errors that a caller could ignore.
 */
export function validateConfig(config: SystemConfig): string[] {
  const errors: string[] = [];
  const critical: string[] = [];

  // Validate network
  if (!["mainnet", "testnet", "regtest", "signet"].includes(config.network)) {
    errors.push(`Invalid network: ${config.network}`);
  }

  // --- Fail-closed security checks (C3) ---------------------------------
  // Insecure key custody must never leave development, and never touch mainnet.
  const outsideDevelopment =
    config.mode !== "development" || config.network === "mainnet";

  if (config.keys.provider === "mock" && outsideDevelopment) {
    critical.push(
      `KEY_PROVIDER=mock derives keys from a world-known test seed; refusing to run ` +
        `with mode=${config.mode} network=${config.network}. Use a cloud KMS provider.`
    );
  }

  if (
    config.keys.provider === "local" &&
    !config.keys.allowLocalKeys &&
    outsideDevelopment
  ) {
    critical.push(
      `KEY_PROVIDER=local keeps the mnemonic in process memory/env; refusing to run ` +
        `with mode=${config.mode} network=${config.network}. Set ALLOW_LOCAL_KEYS=1 to ` +
        `explicitly accept this risk, or use a cloud KMS provider.`
    );
  }

  // Default credentials are never acceptable outside development
  if (config.mode !== "development" && config.api.authKey === DEFAULT_API_AUTH_KEY) {
    critical.push(
      `API_AUTH_KEY is the insecure default; refusing to run with mode=${config.mode}. ` +
        `Set a strong API_AUTH_KEY.`
    );
  }

  if (critical.length > 0) {
    throw new Error(
      `Fatal configuration errors (refusing to start):\n${critical.join("\n")}`
    );
  }
  // ----------------------------------------------------------------------

  // Validate key management
  if (config.keys.provider === "local" && !config.keys.mnemonic) {
    errors.push("Local key provider requires MNEMONIC environment variable");
  }

  if (["gcp", "aws"].includes(config.keys.provider)) {
    if (!config.keys.projectId) {
      errors.push(`Cloud provider requires CLOUD_PROJECT_ID`);
    }
  }

  // Validate database
  if (!config.database.uri) {
    errors.push("Database URI is required");
  }

  // Validate VTXO
  if (config.mode !== "development" && !config.vtxo.serverPublicKey) {
    errors.push("VTXO_SERVER_PUBKEY is required in non-development mode");
  }

  return errors;
}

/**
 * Loads and validates configuration
 */
export function loadConfig(): SystemConfig {
  const config = loadConfigFromEnv();
  const errors = validateConfig(config);

  if (errors.length > 0) {
    throw new Error(`Configuration errors:\n${errors.join("\n")}`);
  }

  // Startup log (C3): surface the key custody and the configured trusted
  // oracle/ASP key so operators can verify what the verifier will pin.
  console.log(
    `[config] mode=${config.mode} network=${config.network} keyProvider=${config.keys.provider}`
  );
  console.log(
    `[config] trusted oracle/ASP key (vtxo.serverPublicKey): ${
      config.vtxo.serverPublicKey || "(unset)"
    }`
  );

  return config;
}
