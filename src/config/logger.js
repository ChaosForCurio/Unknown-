const pino = require("pino");
const env = require("./env");

const isDev = env.NODE_ENV === "development";

const logger = pino({
    level: process.env.LOG_LEVEL || "info",
    redact: ["req.headers.authorization", "password", "token"],
    ...(isDev && {
        transport: {
            target: "pino-pretty",
            options: {
                colorize: true,
                translateTime: "SYS:standard",
            },
        },
    }),
});

module.exports = logger;
