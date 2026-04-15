const jwt = require("jsonwebtoken");
const TokenBlacklist = require("../models/blacklist.model");

/**
 * @name authMiddleware
 * @desc Verifies JWT from cookie and checks if it has been blacklisted
 */
async function authMiddleware(req, res, next) {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: "Authentication required" });
        }

        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Check if this token has been blacklisted (i.e., user logged out)
        if (decoded.jti && (await TokenBlacklist.isBlacklisted(decoded.jti))) {
            return res.status(401).json({ message: "Token has been revoked" });
        }

        // Attach user data and raw token to the request
        req.user = decoded;
        req.token = token;
        next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Token has expired" });
        }
        if (error.name === "JsonWebTokenError") {
            return res.status(401).json({ message: "Invalid token" });
        }
        console.error("authMiddleware error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

module.exports = authMiddleware;
