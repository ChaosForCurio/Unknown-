const crypto = require("crypto");
const User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const TokenBlacklist = require("../models/blacklist.model");
const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");
const env = require("../config/env");

// ── Helpers ───────────────────────────────────────────────

/**
 * Extract the client's real IP from the request.
 */
function getClientIp(req) {
    const forwarded = req.headers["x-forwarded-for"];
    return forwarded ? forwarded.split(",")[0].trim() : req.socket.remoteAddress;
}

/**
 * Sign a JWT with a unique jti and return { token, jti, exp }.
 */
function signToken(payload, expiresIn = "1d") {
    const jti = crypto.randomUUID();
    const token = jwt.sign(payload, env.JWT_SECRET, {
        expiresIn,
        jwtid: jti,
    });
    const decoded = jwt.decode(token);
    return { token, jti, exp: decoded.exp };
}

// ── Controllers ───────────────────────────────────────────

const registerUserController = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    const existingUser = await User.findByUsernameOrEmail(username, email);
    if (existingUser) {
        throw new AppError("Username or email is already taken", 409, "CONFLICT");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, email, password: hashedPassword });

    const { token, jti, exp } = signToken(
        { id: newUser.id, username: newUser.username, email: newUser.email },
        "7d"
    );

    await TokenBlacklist.trackSession(newUser.id, jti, exp, {
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"],
    });

    await TokenBlacklist.recordLoginAttempt(newUser.id, {
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"],
        success: true,
    });

    res.cookie("token", token, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
        message: "User registered successfully",
        user: { id: newUser.id, username: newUser.username, email: newUser.email },
    });
});

const loginUserController = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"];

    const user = await User.findByEmail(email);
    if (!user) {
        throw new AppError("Invalid credentials", 401, "INVALID_CREDENTIALS");
    }

    if (await TokenBlacklist.isLockedOut(user.id)) {
        throw new AppError("Account temporarily locked due to too many failed login attempts. Try again later.", 429, "ACCOUNT_LOCKED");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        const { count, locked } = await TokenBlacklist.recordFailedLogin(
            user.id,
            Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
        );

        await TokenBlacklist.recordLoginAttempt(user.id, { ip, userAgent, success: false });

        if (locked) {
            throw new AppError("Too many failed attempts. All sessions have been revoked.", 429, "SESSIONS_REVOKED");
        }

        throw new AppError(`Invalid credentials. Attempts remaining: ${Math.max(0, 5 - count)}`, 401, "INVALID_CREDENTIALS");
    }

    await TokenBlacklist.resetFailedLogins(user.id);

    const { token, jti, exp } = signToken(
        { id: user.id, username: user.username, email: user.email },
        "1d"
    );

    await TokenBlacklist.trackSession(user.id, jti, exp, { ip, userAgent });

    await TokenBlacklist.recordLoginAttempt(user.id, { ip, userAgent, success: true });

    res.cookie("token", token, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 1 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
        message: "Login successful",
        user: { id: user.id, username: user.username, email: user.email },
    });
});

const logoutUserController = asyncHandler(async (req, res) => {
    const { jti, exp } = req.user;

    if (jti && exp) {
        await TokenBlacklist.add(jti, exp, "logout");
    }

    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out successfully" });
});

const logoutAllController = asyncHandler(async (req, res) => {
    const { id: userId } = req.user;
    const farFuture = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;

    const count = await TokenBlacklist.revokeAllUserSessions(userId, farFuture, "force_logout");

    res.clearCookie("token");
    return res.status(200).json({
        message: `Logged out from all devices. ${count} session(s) revoked.`,
    });
});

const getSessionsController = asyncHandler(async (req, res) => {
    const { id: userId, jti: currentJti } = req.user;
    const sessions = await TokenBlacklist.getActiveSessions(userId);

    const formatted = sessions.map((s) => ({
        ...s,
        isCurrent: s.jti === currentJti,
    }));

    return res.status(200).json({
        sessions: formatted,
        total: formatted.length,
    });
});

const revokeSessionController = asyncHandler(async (req, res) => {
    const { jti: targetJti } = req.params;
    const farFuture = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;

    await TokenBlacklist.add(targetJti, farFuture, "manual_revoke");

    if (targetJti === req.user.jti) {
        res.clearCookie("token");
    }

    return res.status(200).json({ message: "Session revoked successfully" });
});

const getLoginHistoryController = asyncHandler(async (req, res) => {
    const { id: userId } = req.user;
    const history = await TokenBlacklist.getLoginHistory(userId, 20);

    return res.status(200).json({ history });
});

module.exports = {
    registerUserController,
    loginUserController,
    logoutUserController,
    logoutAllController,
    getSessionsController,
    revokeSessionController,
    getLoginHistoryController,
};