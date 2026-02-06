// backend/middleware/auth.js
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret12345";

async function verifyToken(req, res, next) {
    try {
        const auth = req.headers.authorization || req.headers.Authorization;
        if (!auth) return res.status(401).json({ message: "Missing Authorization header" });
        const parts = auth.split(" ");
        if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ message: "Invalid Authorization format" });
        const token = parts[1];
        const payload = jwt.verify(token, JWT_SECRET);
        req.userId = payload.id;
        const user = await User.findById(req.userId).select("role isAdmin").lean();
        if (!user) return res.status(401).json({ message: "Invalid token user" });
        req.userIsAdmin = !!(user.isAdmin || user.role === "admin");
        req.user = user;
        next();
    } catch (err) {
        console.error("verifyToken error", err && err.message);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

function requireAdmin(req, res, next) {
    if (!req.user || !(req.user.isAdmin || req.user.role === "admin")) return res.status(403).json({ message: "Admin required" });
    return next();
}

module.exports = { verifyToken, requireAdmin };
