const { Router } = require("express");
const {
    registerUserController,
    loginUserController,
    logoutUserController,
} = require("../controller/auth.controller");

const authRouter = Router();

/**
 * @route POST /api/auth/register
 * @desc  Register a new user
 * @access Public
 */
authRouter.post("/register", registerUserController);

/**
 * @route POST /api/auth/login
 * @desc  Login a user
 * @access Public
 */
authRouter.post("/login", loginUserController);

/**
 * @route POST /api/auth/logout
 * @desc  Logout the current user
 * @access Public
 */
authRouter.post("/logout", logoutUserController);

module.exports = authRouter;
