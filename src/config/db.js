const { neon } = require("@neondatabase/serverless");
const env = require("./env");
const logger = require("./logger");

let sql;

async function connectDB() {
    try {
        sql = neon(env.NEON_DB);

        // Ensure the users table exists
        await sql`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        `;

        logger.info("Connected to Neon database & users table ready.");
    } catch (error) {
        logger.error({ err: error }, "Error connecting to Neon database");
        process.exit(1);
    }
}

function getSQL() {
    if (!sql) throw new Error("Database not initialized. Call connectDB() first.");
    return sql;
}

module.exports = { connectDB, getSQL };