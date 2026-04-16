const { z } = require("zod");

const registerSchema = z.object({
    username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9]+$/, "Username must be alphanumeric"),
    email: z.string().email(),
    password: z.string().min(8, "Password must be at least 8 characters long")
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1, "Password is required")
});

module.exports = {
    registerSchema,
    loginSchema
};
