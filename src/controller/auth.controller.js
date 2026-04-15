const User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/**
 * @name registerUserController
 * @desc Register a new user, expects username, email and password
 * @route POST /api/auth/register
 * @access Public
 */
async function registerUserController(req, res) {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if user already exists
        const existingUser = await User.findByUsernameOrEmail(username, email);
        if (existingUser) {
            return res.status(409).json({ message: "Username or email is already taken" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = await User.create({ username, email, password: hashedPassword });

        // Sign JWT
        const token = jwt.sign(
            { id: newUser.id, username: newUser.username, email: newUser.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        // Set cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(201).json({
            message: "User registered successfully",
            user: { id: newUser.id, username: newUser.username, email: newUser.email },
        });
    } catch (error) {
        console.error("registerUserController error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

/**
 * @name loginUserController
 * @desc Login a user, expects email and password
 * @route POST /api/auth/login
 * @access Public
 */
async function loginUserController(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Find user
        const user = await User.findByEmail(email);
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Sign JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        // Set cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(200).json({
            message: "Login successful",
            user: { id: user.id, username: user.username, email: user.email },
        });
    } catch (error) {
        console.error("loginUserController error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

/**
 * @name logoutUserController
 * @desc Logout the current user
 * @route POST /api/auth/logout
 * @access Public
 */
async function logoutUserController(req, res) {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logged out successfully" });
}

module.exports = { registerUserController, loginUserController, logoutUserController };