require("dotenv").config({ path: ".env.local" });
const env = require("./config/env");
const logger = require("./config/logger");
const app = require("./app");
const { connectDB } = require("./config/db");

connectDB().then(() => {
    app.listen(env.PORT, () => {
        logger.info(`Server is running on port ${env.PORT}`);
    });
});
