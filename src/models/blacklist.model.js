const redis = require("../config/redis");

// ── Redis Key Prefixes ────────────────────────────────────
const BLACKLIST_PREFIX = "bl:";
const USER_SESSIONS_PREFIX = "sessions:";
const SESSION_META_PREFIX = "session_meta:";
const SESSION_ACTIVITY_PREFIX = "activity:";
const LOGIN_HISTORY_PREFIX = "login_history:";
const FAILED_LOGINS_PREFIX = "failed_logins:";
const GLOBAL_REVOKE_KEY = "global:revoked_before";

// ── Configuration ─────────────────────────────────────────
const MAX_SESSIONS_PER_USER = 5;
const MAX_FAILED_LOGINS = 5;
const FAILED_LOGIN_WINDOW = 15 * 60;       // 15 minutes (seconds)
const IDLE_TIMEOUT = 30 * 60;              // 30 minutes (seconds)
const LOGIN_HISTORY_MAX = 20;              // keep last 20 entries

const TokenBlacklist = {

    // ═══════════════════════════════════════════════════════
    //  1. CORE — Add & Check Blacklist
    // ═══════════════════════════════════════════════════════

    /**
     * Add a token's JTI to the blacklist with an optional reason.
     * TTL is set to the token's remaining lifetime so it auto-expires.
     * @param {string} jti - The JWT ID
     * @param {number} expiresAt - The token's `exp` claim (unix seconds)
     * @param {string} [reason="logout"] - Why the token was blacklisted
     */
    async add(jti, expiresAt, reason = "logout") {
        const ttl = expiresAt - Math.floor(Date.now() / 1000);
        if (ttl <= 0) return; // Token already expired, no need to blacklist
        await redis.set(`${BLACKLIST_PREFIX}${jti}`, reason, { ex: ttl });
    },

    /**
     * Check if a token's JTI is blacklisted.
     * @param {string} jti - The JWT ID
     * @returns {Promise<boolean>}
     */
    async isBlacklisted(jti) {
        const result = await redis.get(`${BLACKLIST_PREFIX}${jti}`);
        return result !== null;
    },

    /**
     * Get the reason a token was blacklisted.
     * @param {string} jti - The JWT ID
     * @returns {Promise<string|null>} - The reason or null if not blacklisted
     */
    async getBlacklistReason(jti) {
        return await redis.get(`${BLACKLIST_PREFIX}${jti}`);
    },

    // ═══════════════════════════════════════════════════════
    //  2. SESSION TRACKING — Per-User Sessions with Metadata
    // ═══════════════════════════════════════════════════════

    /**
     * Register a new session (call after login/register).
     * Stores session metadata (IP, user-agent, timestamp) and
     * enforces the max concurrent session limit.
     * @param {string} userId
     * @param {string} jti
     * @param {number} expiresAt - Token `exp` (unix seconds)
     * @param {object} [meta] - { ip, userAgent }
     */
    async trackSession(userId, jti, expiresAt, meta = {}) {
        const ttl = expiresAt - Math.floor(Date.now() / 1000);
        if (ttl <= 0) return;

        // Store session JTI in the user's session set
        await redis.sadd(`${USER_SESSIONS_PREFIX}${userId}`, jti);
        await redis.expire(`${USER_SESSIONS_PREFIX}${userId}`, ttl);

        // Store session metadata
        const metaPayload = JSON.stringify({
            ip: meta.ip || "unknown",
            userAgent: meta.userAgent || "unknown",
            createdAt: new Date().toISOString(),
        });
        await redis.set(`${SESSION_META_PREFIX}${jti}`, metaPayload, { ex: ttl });

        // Mark session as active (for idle timeout)
        await redis.set(`${SESSION_ACTIVITY_PREFIX}${jti}`, Date.now().toString(), { ex: IDLE_TIMEOUT });

        // Enforce max concurrent sessions
        await this._enforceMaxSessions(userId, expiresAt);
    },

    /**
     * Get all active (non-blacklisted) sessions for a user, with metadata.
     * @param {string} userId
     * @returns {Promise<Array<{jti, ip, userAgent, createdAt}>>}
     */
    async getActiveSessions(userId) {
        const jtis = await redis.smembers(`${USER_SESSIONS_PREFIX}${userId}`);
        const sessions = [];

        for (const jti of jtis) {
            if (await this.isBlacklisted(jti)) continue;

            const raw = await redis.get(`${SESSION_META_PREFIX}${jti}`);
            const meta = raw ? (typeof raw === "string" ? JSON.parse(raw) : raw) : {};
            sessions.push({ jti, ...meta });
        }

        return sessions;
    },

    /**
     * Get count of active sessions for a user.
     * @param {string} userId
     * @returns {Promise<number>}
     */
    async getActiveSessionCount(userId) {
        const sessions = await this.getActiveSessions(userId);
        return sessions.length;
    },

    /**
     * Enforce a maximum number of concurrent sessions.
     * Revokes the oldest session(s) if the limit is exceeded.
     * @private
     */
    async _enforceMaxSessions(userId, expiresAt) {
        const sessions = await this.getActiveSessions(userId);

        if (sessions.length <= MAX_SESSIONS_PER_USER) return;

        // Sort oldest-first by createdAt
        sessions.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

        const excess = sessions.length - MAX_SESSIONS_PER_USER;
        for (let i = 0; i < excess; i++) {
            await this.add(sessions[i].jti, expiresAt, "max_sessions_exceeded");
        }
    },

    // ═══════════════════════════════════════════════════════
    //  3. REVOKE ALL — Force Logout Everywhere
    // ═══════════════════════════════════════════════════════

    /**
     * Blacklist every active session for a user.
     * Use on password change, account compromise, or admin action.
     * @param {string} userId
     * @param {number} expiresAt - A generous expiry (e.g. max token lifetime from now)
     * @param {string} [reason="force_logout"]
     * @returns {Promise<number>} - Number of sessions revoked
     */
    async revokeAllUserSessions(userId, expiresAt, reason = "force_logout") {
        const jtis = await redis.smembers(`${USER_SESSIONS_PREFIX}${userId}`);
        let count = 0;

        for (const jti of jtis) {
            if (!(await this.isBlacklisted(jti))) {
                await this.add(jti, expiresAt, reason);
                count++;
            }
        }

        await redis.del(`${USER_SESSIONS_PREFIX}${userId}`);
        return count;
    },

    // ═══════════════════════════════════════════════════════
    //  4. GLOBAL REVOCATION — Nuclear Option
    // ═══════════════════════════════════════════════════════

    /**
     * Revoke ALL tokens issued before this moment (global security breach).
     * Every token whose `iat` is <= this timestamp will be rejected.
     * @returns {Promise<number>} - The cutoff unix timestamp
     */
    async setGlobalRevocation() {
        const now = Math.floor(Date.now() / 1000);
        await redis.set(GLOBAL_REVOKE_KEY, now.toString());
        return now;
    },

    /**
     * Check if a token was issued before the global revocation cutoff.
     * @param {number} tokenIssuedAt - The token's `iat` claim (unix seconds)
     * @returns {Promise<boolean>}
     */
    async isGloballyRevoked(tokenIssuedAt) {
        const revokedBefore = await redis.get(GLOBAL_REVOKE_KEY);
        if (!revokedBefore) return false;
        return tokenIssuedAt <= parseInt(revokedBefore, 10);
    },

    // ═══════════════════════════════════════════════════════
    //  5. IDLE SESSION TIMEOUT
    // ═══════════════════════════════════════════════════════

    /**
     * Refresh the activity heartbeat for a session.
     * Call this on every authenticated request (in middleware).
     * @param {string} jti
     */
    async touchSession(jti) {
        await redis.set(`${SESSION_ACTIVITY_PREFIX}${jti}`, Date.now().toString(), { ex: IDLE_TIMEOUT });
    },

    /**
     * Check if a session has gone idle (heartbeat expired).
     * @param {string} jti
     * @returns {Promise<boolean>} - true if the session is idle / timed out
     */
    async isSessionIdle(jti) {
        const lastActivity = await redis.get(`${SESSION_ACTIVITY_PREFIX}${jti}`);
        return lastActivity === null;
    },

    // ═══════════════════════════════════════════════════════
    //  6. LOGIN HISTORY — Audit Log
    // ═══════════════════════════════════════════════════════

    /**
     * Record a login event in the user's audit log.
     * @param {string} userId
     * @param {object} details - { ip, userAgent, success }
     */
    async recordLoginAttempt(userId, details = {}) {
        const entry = JSON.stringify({
            ip: details.ip || "unknown",
            userAgent: details.userAgent || "unknown",
            success: details.success !== false,
            timestamp: new Date().toISOString(),
        });

        const key = `${LOGIN_HISTORY_PREFIX}${userId}`;
        await redis.lpush(key, entry);
        await redis.ltrim(key, 0, LOGIN_HISTORY_MAX - 1);
        await redis.expire(key, 90 * 24 * 60 * 60); // keep 90 days
    },

    /**
     * Get recent login history for a user.
     * @param {string} userId
     * @param {number} [count=10]
     * @returns {Promise<Array>}
     */
    async getLoginHistory(userId, count = 10) {
        const raw = await redis.lrange(`${LOGIN_HISTORY_PREFIX}${userId}`, 0, count - 1);
        return raw.map((entry) => (typeof entry === "string" ? JSON.parse(entry) : entry));
    },

    // ═══════════════════════════════════════════════════════
    //  7. FAILED LOGIN TRACKING — Brute-Force Protection
    // ═══════════════════════════════════════════════════════

    /**
     * Increment the failed login counter for a user.
     * If the threshold is reached, auto-revoke all sessions.
     * @param {string} userId
     * @param {number} expiresAt - A generous expiry for blacklisting
     * @returns {Promise<{count: number, locked: boolean}>}
     */
    async recordFailedLogin(userId, expiresAt) {
        const key = `${FAILED_LOGINS_PREFIX}${userId}`;
        const count = await redis.incr(key);

        // Set the sliding window only on the first failure
        if (count === 1) {
            await redis.expire(key, FAILED_LOGIN_WINDOW);
        }

        let locked = false;
        if (count >= MAX_FAILED_LOGINS) {
            await this.revokeAllUserSessions(userId, expiresAt, "too_many_failed_logins");
            locked = true;
        }

        return { count, locked };
    },

    /**
     * Reset the failed login counter (call on successful login).
     * @param {string} userId
     */
    async resetFailedLogins(userId) {
        await redis.del(`${FAILED_LOGINS_PREFIX}${userId}`);
    },

    /**
     * Check if a user is currently locked out.
     * @param {string} userId
     * @returns {Promise<boolean>}
     */
    async isLockedOut(userId) {
        const count = await redis.get(`${FAILED_LOGINS_PREFIX}${userId}`);
        return count !== null && parseInt(count, 10) >= MAX_FAILED_LOGINS;
    },

    // ═══════════════════════════════════════════════════════
    //  8. STATS / METRICS
    // ═══════════════════════════════════════════════════════

    /**
     * Get a summary of blacklist & session stats (for admin dashboards).
     * @param {string} [userId] - Optional: scope stats to a single user
     * @returns {Promise<object>}
     */
    async getStats(userId) {
        const stats = {};

        if (userId) {
            stats.activeSessions = await this.getActiveSessionCount(userId);
            stats.isLockedOut = await this.isLockedOut(userId);
        }

        // Global revocation timestamp
        const globalRevoke = await redis.get(GLOBAL_REVOKE_KEY);
        stats.globalRevokedBefore = globalRevoke
            ? new Date(parseInt(globalRevoke, 10) * 1000).toISOString()
            : null;

        return stats;
    },
};

module.exports = TokenBlacklist;
