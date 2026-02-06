// backend/routes/admin_payments.js
const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const PaymentMethod = require("../models/PaymentMethod");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret12345";

// simple admin middleware (matches earlier verifyToken semantics)
async function verifyAdmin(req, res, next) {
    try {
        const auth = req.headers.authorization || req.headers.Authorization;
        if (!auth) return res.status(401).json({ message: "Missing Authorization" });
        const parts = auth.split(" ");
        if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ message: "Invalid Authorization format" });
        const token = parts[1];
        const payload = jwt.verify(token, JWT_SECRET);
        if (!payload || !payload.id) return res.status(401).json({ message: "Invalid token" });

        const user = await User.findById(payload.id).select("role isAdmin").lean();
        if (!user) return res.status(401).json({ message: "Invalid token user" });
        const isAdmin = !!(user.role === "admin" || user.isAdmin);
        if (!isAdmin) return res.status(403).json({ message: "Forbidden" });

        req.adminUser = user;
        next();
    } catch (err) {
        console.error("verifyAdmin error", err && err.message);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// GET /api/admin/payments/methods
router.get("/methods", verifyAdmin, async (req, res) => {
    try {
        const methods = await PaymentMethod.find({}).sort({ createdAt: -1 }).lean();
        return res.json({ methods });
    } catch (err) {
        console.error("GET /api/admin/payments/methods error", err);
        return res.status(500).json({ message: "Server error" });
    }
});

// GET single
router.get("/methods/:id", verifyAdmin, async (req, res) => {
    try {
        const m = await PaymentMethod.findById(req.params.id).lean();
        if (!m) return res.status(404).json({ message: "Not found" });
        return res.json({ method: m });
    } catch (err) {
        console.error("GET /api/admin/payments/methods/:id", err);
        return res.status(500).json({ message: "Server error" });
    }
});

// POST /api/admin/payments/methods  (create)
router.post("/methods", verifyAdmin, async (req, res) => {
    try {
        const { name, type, details } = req.body;
        if (!name || !type) return res.status(400).json({ message: "name & type required" });
        const m = new PaymentMethod({ name, type, details: details || {} });
        await m.save();
        return res.status(201).json({ method: m });
    } catch (err) {
        console.error("POST /api/admin/payments/methods err", err);
        return res.status(500).json({ message: "Server error" });
    }
});

// PATCH /api/admin/payments/methods/:id (update)
router.patch("/methods/:id", verifyAdmin, async (req, res) => {
    try {
        const updates = req.body || {};
        const m = await PaymentMethod.findByIdAndUpdate(req.params.id, { $set: updates }, { new: true }).lean();
        if (!m) return res.status(404).json({ message: "Not found" });
        return res.json({ method: m });
    } catch (err) {
        console.error("PATCH /api/admin/payments/methods/:id err", err);
        return res.status(500).json({ message: "Server error" });
    }
});

// DELETE /api/admin/payments/methods/:id
router.delete("/methods/:id", verifyAdmin, async (req, res) => {
    try {
        await PaymentMethod.findByIdAndDelete(req.params.id);
        return res.json({ message: "Deleted" });
    } catch (err) {
        console.error("DELETE /api/admin/payments/methods/:id err", err);
        return res.status(500).json({ message: "Server error" });
    }
});

module.exports = router;
