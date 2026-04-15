const { neon } = require("@neondatabase/serverless");

let sql;

async function connectDB() {
    try {
        sql = neon(process.env.NEON_DB);

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

        console.log("Connected to Neon database & users table ready.");
    } catch (error) {
        console.error("Error connecting to Neon database:", error);
        process.exit(1);
    }
}

function getSQL() {
    if (!sql) throw new Error("Database not initialized. Call connectDB() first.");
    return sql;
}

module.exports = { connectDB, getSQL };