const { Redis } = require("@upstash/redis");
const env = require("./env");

const redis = new Redis({
    url: env.UPSTASH_REDIS_REST_URL,
    token: env.UPSTASH_REDIS_REST_TOKEN,
});

module.exports = redis;
