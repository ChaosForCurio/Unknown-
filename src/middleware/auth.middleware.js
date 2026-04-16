const jwt = require("jsonwebtoken");
const TokenBlacklist = require("../models/blacklist.model");
const AppError = require("../utils/AppError");
const env = require("../config/env");

/**
 * @name authMiddleware
 * @desc Verifies JWT from cookie and checks:
 *       1. Token signature & expiry
 *       2. Token blacklist (user logged out)
 *       3. Global revocation (security breach)
 *       4. Idle session timeout (no recent activity)
 *       Then refreshes the session heartbeat.
 */
async function authMiddleware(req, res, next) {
    try {
        const token = req.cookies.token;

        if (!token) {
            throw new AppError("Authentication required", 401, "UNAUTHORIZED");
        }

        // Verify the token
        const decoded = jwt.verify(token, env.JWT_SECRET);

        // Check if this token has been blacklisted (i.e., user logged out)
        if (decoded.jti && (await TokenBlacklist.isBlacklisted(decoded.jti))) {
            throw new AppError("Token has been revoked", 401, "TOKEN_REVOKED");
        }

        // Check global revocation (e.g., after a security breach)
        if (decoded.iat && (await TokenBlacklist.isGloballyRevoked(decoded.iat))) {
            throw new AppError("All sessions have been revoked. Please log in again.", 401, "GLOBAL_REVOCATION");
        }

        // Check idle session timeout
        if (decoded.jti && (await TokenBlacklist.isSessionIdle(decoded.jti))) {
            throw new AppError("Session timed out due to inactivity", 401, "SESSION_TIMEOUT");
        }

        // Refresh the activity heartbeat
        if (decoded.jti) {
            await TokenBlacklist.touchSession(decoded.jti);
        }

        // Attach user data and raw token to the request
        req.user = decoded;
        req.token = token;
        next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            next(new AppError("Token has expired", 401, "TOKEN_EXPIRED"));
        } else if (error.name === "JsonWebTokenError") {
            next(new AppError("Invalid token", 401, "INVALID_TOKEN"));
        } else {
            next(error);
        }
    }
}

module.exports = authMiddleware;
