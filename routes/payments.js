// backend/routes/payments.js
const express = require("express");
const router = express.Router();
const PaymentMethod = require("../models/PaymentMethod");

// GET /api/payments/methods?type=btc
router.get("/methods", async (req, res) => {
    try {
        const type = (req.query.type || "").toString().trim();
        const q = {};
        if (type) q.type = type;
        const methods = await PaymentMethod.find(q).sort({ createdAt: -1 }).lean();
        return res.json({ methods });
    } catch (err) {
        console.error("GET /api/payments/methods error", err);
        return res.status(500).json({ message: "Server error" });
    }
});

// GET /api/payments/methods/:id
router.get("/methods/:id", async (req, res) => {
    try {
        const m = await PaymentMethod.findById(req.params.id).lean();
        if (!m) return res.status(404).json({ message: "Not found" });
        return res.json({ method: m });
    } catch (err) {
        console.error("GET /api/payments/methods/:id error", err);
        return res.status(500).json({ message: "Server error" });
    }
});

module.exports = router;
