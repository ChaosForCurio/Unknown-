const { getSQL } = require("../config/db");

const User = {
    /**
     * Find a user by username OR email
     */
    async findByUsernameOrEmail(username, email) {
        const sql = getSQL();
        const rows = await sql`
            SELECT * FROM users
            WHERE username = ${username} OR email = ${email}
            LIMIT 1
        `;
        return rows[0] || null;
    },

    /**
     * Find a user by email
     */
    async findByEmail(email) {
        const sql = getSQL();
        const rows = await sql`
            SELECT * FROM users
            WHERE email = ${email}
            LIMIT 1
        `;
        return rows[0] || null;
    },

    /**
     * Create a new user and return the created row
     */
    async create({ username, email, password }) {
        const sql = getSQL();
        const rows = await sql`
            INSERT INTO users (username, email, password)
            VALUES (${username}, ${email}, ${password})
            RETURNING id, username, email, created_at
        `;
        return rows[0];
    },
};

module.exports = User;