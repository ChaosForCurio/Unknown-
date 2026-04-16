const swaggerJsdoc = require("swagger-jsdoc");
const env = require("./env");

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Gen-AI Auth API",
            version: "1.0.0",
            description: "Authentication backend API",
        },
        servers: [
            {
                url: `http://localhost:${env.PORT}`,
                description: "Development server",
            },
        ],
        components: {
            securitySchemes: {
                cookieAuth: {
                    type: "apiKey",
                    in: "cookie",
                    name: "token",
                },
            },
        },
    },
    apis: ["./src/routes/*.js"],
};

const specs = swaggerJsdoc(options);

module.exports = specs;
