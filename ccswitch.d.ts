// Hand-maintained declarations for ccswitch.mjs. The library test checks that
// the value exports declared here match the module's runtime exports exactly.

export type Target = 'claude' | 'kimi';

interface BaseConfig {
  target: Target;
  progBin: string;
  prog: string;
  toolName: string;
  home: string;
  usageCacheDir: string;
  credentialsFile: string;
  bin: string;
  loginArgs: string[];
  runEnvVar: 'CLAUDE_CONFIG_DIR' | 'KIMI_CODE_HOME';
  procName: 'claude' | 'kimi';
}

export interface ClaudeConfig extends BaseConfig {
  target: 'claude';
  keychainService: string;
  claudeJson: string;
  claudeBin: string;
  runEnvVar: 'CLAUDE_CONFIG_DIR';
  procName: 'claude';
}

export interface KimiConfig extends BaseConfig {
  target: 'kimi';
  kimiHome: string;
  kimiBin: string;
  runEnvVar: 'KIMI_CODE_HOME';
  procName: 'kimi';
  keychainService?: undefined;
  claudeJson?: undefined;
}

export type Config = ClaudeConfig | KimiConfig;

// The oauthAccount record claude keeps in ~/.claude.json (a subset of its keys).
export interface ClaudeOauthAccount {
  accountUuid?: string;
  emailAddress?: string;
  organizationUuid?: string;
  organizationName?: string;
  organizationRateLimitTier?: string;
  userRateLimitTier?: string;
  displayName?: string;
  [key: string]: unknown;
}

// Kimi has no identity file: userId comes from the access-token JWT, the
// display fields from best-effort /me lookups, the endpoints from config.toml.
export interface KimiOauthAccount {
  userId?: string;
  nickname?: string | null;
  email?: string | null;
  userLevelName?: string | null;
  baseUrl?: string;
  oauthHost?: string;
}

export type OauthAccount = ClaudeOauthAccount | KimiOauthAccount;

// credentials is the raw credentials file text (secrets), null when unknown.
export interface Profile {
  credentials: string | null;
  oauthAccount: OauthAccount | null;
  savedAt: string;
  movedAt?: string;
}

export interface ProfileEntry extends Profile {
  name: string;
}

export interface ProfileInput {
  credentials: string | null;
  oauthAccount: OauthAccount | null;
  savedAt?: string;
  movedAt?: string;
}

export interface LiveCapture {
  credentials: string | null;
  oauthAccount: OauthAccount | null;
}

export interface UsageWindow {
  utilization: number | null;
  resetsAt: string | null;
}

export interface ClaudeUsage {
  fiveHour: UsageWindow | null;
  sevenDay: UsageWindow | null;
  fable: UsageWindow | null;
}

export interface KimiUsageRow {
  name: string | null;
  label: string | null;
  used: number;
  limit: number;
  utilization: number | null;
  resetsAt: string | null;
}

export interface KimiBooster {
  balanceCents: number;
  totalCents: number;
  currency: string;
}

export interface KimiUsage {
  summary: KimiUsageRow | null;
  limits: KimiUsageRow[];
  booster: KimiBooster | null;
}

export type Usage = ClaudeUsage | KimiUsage;

export interface UsageCacheRecord<U = Usage> {
  fetchedAt: number;
  usage: U;
}

export type Status =
  | { kind: 'ok' }
  | { kind: 'cached'; at: number }
  | { kind: 'dead' }
  | { kind: 'moved' }
  | { kind: 'error'; message: string };

export interface KimiConnection {
  baseUrl: string;
  oauthHost: string;
}

export interface KimiUserInfo {
  userId: string;
  nickname: string | null;
  email: string | null;
  userLevelName: string | null;
}

export interface KimiWindow {
  duration: number;
  unit: 'minute' | 'hour' | 'day' | 'week';
}

// A profile as list/usage report it: the identity fields, never the credentials.
export interface ProfileSummary {
  name: string;
  active: boolean;
  moved: boolean;
  account: string | null;
  tier: string | null;
  accountId: string | null;
  subscriptionType: string | null;
  tokenExpiresAt: string | null;
  savedAt: string | null;
}

export interface ProfileRecord<U = Usage> extends ProfileSummary {
  usage: U | null;
  cachedAt: number | null;
  state: Status;
}

export interface ProfileList {
  target: Target;
  active: string | null;
  profiles: ProfileSummary[];
}

export interface UsageReport<U = Usage> {
  target: Target;
  active: string | null;
  fetchedAt: number;
  profiles: ProfileRecord<U>[];
}

export interface LiveIdentity {
  loggedIn: boolean;
  account: string | null;
  tier: string | null;
  accountId: string | null;
  subscriptionType: string | null;
  rateLimitTier: string | null;
  tokenExpiresAt: string | null;
  profile: string | null;
}

export interface LiveUsage<U = Usage> {
  usage: U | null;
  cachedAt: number | null;
  state: Status;
}

// A materialized run dir plus what to spawn: spread env over the child's
// environment and call finish() after it exits to save rotated tokens back.
export interface RunHandle {
  bin: string;
  dir: string;
  env: Record<string, string>;
  profile: { name: string; account: string | null; tier: string | null };
  finish(): { savedBack: boolean };
}

export interface KeychainEntryReport {
  name: string;
  service: string;
  present: boolean | null;
}

export interface KeychainReport {
  available: boolean;
  locked: boolean | null;
  lockProbeStatus: number | null;
  defaultEntry: { service: string; present: boolean | null } | null;
  runDirEntries: KeychainEntryReport[];
}

export interface DoctorReport {
  target: Target;
  platform: string;
  node: string;
  bin: { name: string; found: string | null };
  store: {
    home: string;
    exists: boolean;
    encrypted: boolean;
    readable: boolean;
    profiles: string[] | null;
    active: string | null;
    runDirs: string[];
  };
  credentialsFile: { path: string; present: boolean };
  live: LiveIdentity;
  keychain: KeychainReport | null;
}

// Anything shaped like fetch; tests pass fakes returning only these fields.
export type FetchImpl = (url: string, init?: RequestInit) => Promise<Pick<Response, 'ok' | 'status' | 'json'>>;

export class UsageError extends Error {}
export class CancelledError extends Error {}
export class AuthDeadError extends Error {}
export class RateLimitedError extends Error {}

export function asCancel(err: unknown): unknown;
export function progName(): 'ccswitch' | 'kcswitch';
export function defaultTarget(): Target;
export function config(target: 'claude'): ClaudeConfig;
export function config(target: 'kimi'): KimiConfig;
export function config(target?: Target): Config;
export function validateName(name: unknown): string;
export function ensureHome(cfg?: Config): void;

export function readKeychainEntry(cfg?: Config): string | null;
export function evictKeychainEntry(cfg?: Config): void;
export function keychainServiceFor(configDir: string, cfg?: Config): string | null;

export function readCredentials(cfg?: Config): string | null;
export function writeCredentials(payload: string, cfg?: Config): void;
export function deleteCredentials(cfg?: Config): void;
export function readClaudeJson(cfg?: Config): Record<string, unknown>;
export function updateOauthAccount(oauthAccount: OauthAccount | null, cfg?: Config): void;

export function decodeJwtPayload(token: unknown): Record<string, unknown> | null;
export function kimiIdentityFromCredentials(credentials: string | null): { userId: string } | null;
export function readKimiConnection(cfg?: KimiConfig): KimiConnection;

export function encryptText(plain: string, passphrase: string): string;
export function decryptText(raw: string | object, passphrase: string): string;
export function isEncrypted(raw: string): boolean;
export function setPassphrase(p: string | null): void;
export function requirePassphrase(opts?: { confirm?: boolean }): Promise<string>;

export function saveProfile(name: string, profile: ProfileInput, cfg?: Config): void;
export function loadProfile(name: string, cfg?: Config): Profile;
export function profileExists(name: string, cfg?: Config): boolean;
export function listProfiles(cfg?: Config): ProfileEntry[];
export function deleteProfileFile(name: string, cfg?: Config): void;
export function getActive(cfg?: Config): string | null;
export function setActive(name: string | null, cfg?: Config): void;
export function storeEncrypted(cfg?: Config): boolean;
export function writeBackup(reason: string, payload: unknown, cfg?: Config): string;

export function captureLive(cfg?: Config): LiveCapture;
export function warnIfToolRunning(cfg?: Config): void;
export function warnIfClaudeRunning(): void;
export function switchTo(name: string, opts?: { dryRun?: boolean }, cfg?: Config): void;
export function tokenExpiry(credentials: string | null): string;
export function formatList(cfg?: Config): string;
export function deleteProfileCmd(name: string, opts?: { force?: boolean; dryRun?: boolean }, cfg?: Config): Promise<void>;
export function saveCurrent(name: string, opts?: { force?: boolean; dryRun?: boolean }, cfg?: Config): void;
export function login(
  name: string,
  opts?: { force?: boolean; dryRun?: boolean; region?: string | null; fetchImpl?: FetchImpl },
  cfg?: Config,
): Promise<void>;

export function exportProfile(
  name: string,
  dest: string | undefined,
  opts?: { force?: boolean; move?: boolean; dryRun?: boolean },
  cfg?: Config,
): string;
export function importProfile(name: string, src: string | undefined, opts?: { force?: boolean; dryRun?: boolean }, cfg?: Config): void;
export function setStoreEncryption(enabled: boolean, cfg?: Config): void;
export function exportAll(
  dest: string | undefined,
  opts?: { force?: boolean; move?: boolean; dryRun?: boolean },
  cfg?: Config,
): string;
export function importAll(src: string | undefined, opts?: { force?: boolean; dryRun?: boolean }, cfg?: Config): void;

export function materializeRunDir(name: string, cfg?: Config): string;
export function saveBackRunDir(name: string, dir: string, cfg?: Config): boolean;
export function prepareRun(name: string, cfg?: Config): RunHandle;
export function runProfile(name: string, toolArgs: string[], cfg?: Config): number;

export function writeUsageCache(name: string, usage: Usage, cfg?: Config, now?: number): void;
export function readUsageCache(name: string, cfg?: Config): UsageCacheRecord | null;
export function formatAgo(ms: number, now?: number): string;
export function tokenExpired(credentials: string | null, now?: number): boolean;
export function refreshCredentials(credentials: string, fetchImpl?: FetchImpl): Promise<string>;
export function parseFableLimit(body: unknown): UsageWindow | null;
export function parseUsage(body: unknown): ClaudeUsage;
export function fetchUsage(credentials: string, fetchImpl?: FetchImpl): Promise<ClaudeUsage>;

export function refreshKimiCredentials(credentials: string, fetchImpl?: FetchImpl, opts?: { oauthHost?: string }): Promise<string>;
export function kimiWindowLabel(window: KimiWindow | null): string | null;
export function parseKimiUsage(body: unknown): KimiUsage;
export function fetchKimiUsage(credentials: string, fetchImpl?: FetchImpl, opts?: { baseUrl?: string }): Promise<KimiUsage>;
export function fetchKimiUserInfo(baseUrl: string, accessToken: string, fetchImpl?: FetchImpl): Promise<KimiUserInfo | null>;
export function enrichKimiIdentity(
  credentials: string,
  identity: KimiOauthAccount | null,
  cfg?: KimiConfig,
  fetchImpl?: FetchImpl,
): Promise<KimiOauthAccount>;

export function formatCents(cents: number, currency: string): string;
export function formatBar(utilization: number | null, opts?: { color?: boolean }): string;
export function formatStatus(status: Status, opts?: { color?: boolean; now?: number }): string;
export function formatResetIn(resetsAt: string | null, now?: number): string;
export function renderTable(header: string[], rows: string[][], maxWidth?: number): string;
export function shouldUseColor(env?: Record<string, string | undefined>): boolean;
export function listProfileRecords(cfg?: Config): ProfileList;
export function listProfilesWithUsage(opts: { refresh?: boolean }, cfg: ClaudeConfig, fetchImpl?: FetchImpl): Promise<UsageReport<ClaudeUsage>>;
export function listProfilesWithUsage(opts: { refresh?: boolean }, cfg: KimiConfig, fetchImpl?: FetchImpl): Promise<UsageReport<KimiUsage>>;
export function listProfilesWithUsage(opts?: { refresh?: boolean }, cfg?: Config, fetchImpl?: FetchImpl): Promise<UsageReport>;
export function liveIdentity(cfg?: Config): LiveIdentity;
export function liveUsage(opts: { refresh?: boolean }, cfg: ClaudeConfig, fetchImpl?: FetchImpl): Promise<LiveUsage<ClaudeUsage>>;
export function liveUsage(opts: { refresh?: boolean }, cfg: KimiConfig, fetchImpl?: FetchImpl): Promise<LiveUsage<KimiUsage>>;
export function liveUsage(opts?: { refresh?: boolean }, cfg?: Config, fetchImpl?: FetchImpl): Promise<LiveUsage>;
export function usageCmd(opts?: { dryRun?: boolean; json?: boolean; cached?: boolean }, cfg?: Config, fetchImpl?: FetchImpl): Promise<number>;
export function kimiUsageCmd(opts?: { dryRun?: boolean; json?: boolean; cached?: boolean }, cfg?: KimiConfig, fetchImpl?: FetchImpl): Promise<number>;
export function doctor(cfg?: Config): DoctorReport;

export function main(argv?: string[]): Promise<number>;
export function reportFatal(err: unknown): number;
