const redis = require("../config/redis");

const BLACKLIST_PREFIX = "bl:";

const TokenBlacklist = {
    /**
     * Add a token's JTI to the blacklist.
     * TTL is set to the token's remaining lifetime so it auto-expires.
     * @param {string} jti - The JWT ID
     * @param {number} expiresAt - The token's `exp` claim (unix seconds)
     */
    async add(jti, expiresAt) {
        const ttl = expiresAt - Math.floor(Date.now() / 1000);
        if (ttl <= 0) return; // Token already expired, no need to blacklist
        await redis.set(`${BLACKLIST_PREFIX}${jti}`, "1", { ex: ttl });
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
};

module.exports = TokenBlacklist;
