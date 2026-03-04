const { neon } = require("@neondatabase/serverless");

async function connectDB() {
    try {
        await neon(process.env.NEON_DB);
        console.log("Connected to Neon database");
    } catch (error) {
        console.error("Error connecting to Neon database:", error);
    }
}

module.exports = connectDB;