const neon = require("@neondatabase/serverless");

const userSchema = new neon.Schema({
    username: {
        type: String,
        required: true,
        unique: [true, "username already has been taken"]
    },
    email: {
        type: String,
        required: true,
        unique: [true, "email already has been taken"]
    },
    password: {
        type: String,
        required: true,
        unique: true
    }
});

const User = neon.model("User", userSchema);

module.exports = User;