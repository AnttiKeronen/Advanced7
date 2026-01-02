"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateToken = validateToken;
var jsonwebtoken_1 = require("jsonwebtoken");
var SECRET = process.env.SECRET;
function validateToken(req, res, next) {
    var authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.sendStatus(401);
    }
    var token = authHeader.split(" ")[1];
    try {
        jsonwebtoken_1.default.verify(token, SECRET);
        next();
    }
    catch (_a) {
        return res.sendStatus(401);
    }
}
