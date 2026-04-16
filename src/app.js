const express = require("express");
const cookieParser = require("cookie-parser");
const swaggerUi = require("swagger-ui-express");
const swaggerSpecs = require("./config/swagger");
const errorHandler = require("./middleware/errorHandler");

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

/**
 * Routes
 */
const authRouter = require("./routes/auth.routes");

app.use("/api/auth", authRouter);

app.use(errorHandler);

module.exports = app;