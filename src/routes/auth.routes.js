const { Router } = require("express");
const {
    registerUserController,
    loginUserController,
    logoutUserController,
} = require("../controller/auth.controller");
const authMiddleware = require("../middleware/auth.middleware");

const authRouter = Router();

/**
 * @route POST /api/auth/register
 * @desc  Register a new user
 * @access Public
 */
authRouter.post("/register", registerUserController);

/**
 * @route POST /api/auth/login
 * @desc  Login a user with email & password
 * @access Public
 */
authRouter.post("/login", loginUserController);

/**
 * @route POST /api/auth/logout
 * @desc  Logout the current user (blacklists the token)
 * @access Private
 */
authRouter.post("/logout", authMiddleware, logoutUserController);

module.exports = authRouter;
