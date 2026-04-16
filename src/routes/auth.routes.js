const { Router } = require("express");
const {
    registerUserController,
    loginUserController,
    logoutUserController,
    logoutAllController,
    getSessionsController,
    revokeSessionController,
    getLoginHistoryController,
} = require("../controller/auth.controller");
const authMiddleware = require("../middleware/auth.middleware");
const validate = require("../middleware/validate");
const { registerSchema, loginSchema } = require("../schemas/auth.schemas");

const authRouter = Router();

// ── Public Routes ─────────────────────────────────────────

/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation Error
 */
authRouter.post("/register", validate(registerSchema), registerUserController);

/**
 * @openapi
 * /api/auth/login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
authRouter.post("/login", validate(loginSchema), loginUserController);

// ── Private Routes (require valid JWT) ───────────────────

/**
 * @openapi
 * /api/auth/logout:
 *   post:
 *     summary: Logout current device
 *     tags: [Auth]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 *       401:
 *         description: Unauthorized
 */
authRouter.post("/logout", authMiddleware, logoutUserController);

/**
 * @openapi
 * /api/auth/logout-all:
 *   post:
 *     summary: Logout from every device
 *     tags: [Auth]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all devices
 */
authRouter.post("/logout-all", authMiddleware, logoutAllController);

/**
 * @openapi
 * /api/auth/sessions:
 *   get:
 *     summary: Get all active sessions
 *     tags: [Auth]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Returns session list
 */
authRouter.get("/sessions", authMiddleware, getSessionsController);

/**
 * @openapi
 * /api/auth/sessions/{jti}:
 *   delete:
 *     summary: Revoke a specific session
 *     tags: [Auth]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: jti
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session revoked successfully
 */
authRouter.delete("/sessions/:jti", authMiddleware, revokeSessionController);

/**
 * @openapi
 * /api/auth/login-history:
 *   get:
 *     summary: Get login history
 *     tags: [Auth]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Returns array of past logins
 */
authRouter.get("/login-history", authMiddleware, getLoginHistoryController);

module.exports = authRouter;
