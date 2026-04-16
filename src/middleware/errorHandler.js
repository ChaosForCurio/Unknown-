const { ZodError } = require("zod");
const AppError = require("../utils/AppError");
const logger = require("../config/logger");

const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    error.message = err.message;
    
    // Log non-operational errors
    if (!err.isOperational && !(err instanceof ZodError)) {
        logger.error({ err, req }, "Unhandled Exception");
    } else {
        logger.warn({ err }, "Operational Error");
    }

    // Zod Validation Error
    if (err instanceof ZodError) {
        return res.status(400).json({
            success: false,
            error: {
                message: "Validation Error",
                code: "VALIDATION_FAILED",
                details: err.issues.map(issue => ({
                    field: issue.path.join('.'),
                    message: issue.message
                }))
            }
        });
    }

    // AppError
    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            success: false,
            error: {
                message: err.message,
                code: err.code
            }
        });
    }

    // Fallback unhandled error
    return res.status(500).json({
        success: false,
        error: {
            message: process.env.NODE_ENV === "development" ? err.message : "Internal Server Error",
            code: "INTERNAL_ERROR"
        }
    });
};

module.exports = errorHandler;
