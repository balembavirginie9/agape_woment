// backend/controllers/paymentController.js
const PaymentMethod = require("../models/PaymentMethod");
const TransferRequest = require("../models/TransferRequest");
const User = require("../models/User");
const { sendMail } = require("../utils/mail"); // optional

// Admin: list methods
async function listMethods(req, res) {
    try {
        const methods = await PaymentMethod.find().sort({ createdAt: -1 }).lean();
        return res.json({ methods });
    } catch (err) {
        console.error("listMethods", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// Admin: create method
async function createMethod(req, res) {
    try {
        const { name, type, currency, details, qrImageUrl } = req.body;
        if (!name || !type) return res.status(400).json({ message: "Missing fields" });
        const m = new PaymentMethod({ name, type, currency: currency || "USD", details: details || {}, qrImageUrl: qrImageUrl || "" });
        await m.save();
        return res.status(201).json({ message: "Created", method: m });
    } catch (err) {
        console.error("createMethod", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// Admin: update method
async function updateMethod(req, res) {
    try {
        const id = req.params.id;
        const updates = req.body || {};
        const m = await PaymentMethod.findByIdAndUpdate(id, { $set: updates }, { new: true }).lean();
        if (!m) return res.status(404).json({ message: "Not found" });
        return res.json({ message: "Updated", method: m });
    } catch (err) {
        console.error("updateMethod", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// Admin: delete method
async function deleteMethod(req, res) {
    try {
        const id = req.params.id;
        const m = await PaymentMethod.findByIdAndDelete(id).lean();
        if (!m) return res.status(404).json({ message: "Not found" });
        return res.json({ message: "Deleted", methodId: id });
    } catch (err) {
        console.error("deleteMethod", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// Admin: list transfer requests
async function listTransferRequests(req, res) {
    try {
        const status = req.query.status || "pending";
        const q = status === "all" ? {} : { status };
        const list = await TransferRequest.find(q).sort({ createdAt: -1 }).limit(500).lean();
        return res.json({ requests: list });
    } catch (err) {
        console.error("listTransferRequests", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// Admin: process transfer request (approve/decline/investigate)
async function actionTransferRequest(req, res) {
    try {
        const id = req.params.id;
        const { action, message } = req.body;
        if (!["approve", "decline", "investigation"].includes(action)) return res.status(400).json({ message: "Invalid action" });
        const tr = await TransferRequest.findById(id);
        if (!tr) return res.status(404).json({ message: "Not found" });

        if (action === "decline") {
            tr.status = "declined";
            tr.adminMessage = message || "Declined by admin";
            tr.processedBy = req.userId;
            tr.processedAt = new Date();
            await tr.save();
            // refund not necessary (it was a top-up request) — extend logic if needed
        } else if (action === "investigation") {
            tr.status = "investigation";
            tr.adminMessage = message || "Marked for investigation";
            tr.processedBy = req.userId;
            tr.processedAt = new Date();
            await tr.save();
        } else if (action === "approve") {
            tr.status = "approved";
            tr.adminMessage = message || "Approved";
            tr.processedBy = req.userId;
            tr.processedAt = new Date();

            // credit user balance (if top-up)
            const user = await User.findById(tr.userId);
            if (user) {
                user.balance = (user.balance || 0) + (tr.amount || 0);
                await user.save();

                // create Transaction record optionally (reuse Transaction model)
                const Transaction = require("../models/Transaction");
                const tx = new Transaction({
                    userId: user._id,
                    counterpartyAccount: tr.methodSnapshot && tr.methodSnapshot.type ? tr.methodSnapshot.type.toUpperCase() : "ADMIN",
                    counterpartyName: tr.methodSnapshot && tr.methodSnapshot.name ? tr.methodSnapshot.name : "Top-up",
                    type: "credit",
                    amount: tr.amount,
                    fee: 0,
                    description: `Top-up approved (${tr._id})`,
                    createdAt: new Date(),
                });
                await tx.save();
            }
            await tr.save();
        }

        // try notify user
        try {
            const u = await User.findById(tr.userId).select("email firstName").lean();
            if (u && u.email) {
                await sendMail({
                    to: u.email,
                    subject: `Transfer request ${tr._id} - ${tr.status}`,
                    html: `<p>Hi ${u.firstName || ""},</p><p>Your transfer/top-up request (${tr._id}) status changed to <strong>${tr.status}</strong>.</p><p>${tr.adminMessage || ""}</p>`,
                });
            }
        } catch (e) { console.warn("notify fail", e && e.message); }

        return res.json({ message: "Action applied", request: tr });
    } catch (err) {
        console.error("actionTransferRequest", err);
        return res.status(500).json({ message: "Server error" });
    }
}

// User: create a transfer/topup request
async function createTransferRequest(req, res) {
    try {
        const userId = req.userId;
        const { methodId, amount, description } = req.body;
        if (!methodId || !amount) return res.status(400).json({ message: "methodId and amount required" });
        const method = await PaymentMethod.findById(methodId).lean();
        if (!method) return res.status(404).json({ message: "Payment method not found" });

        let screenshotUrl = "";
        // if file uploaded via multer, req.file available (routes can attach multer). For now, allow optional screenshot url in body
        if (req.file && req.file.filename) {
            screenshotUrl = `/uploads/topups/${req.file.filename}`;
        } else if (req.body.screenshot) {
            screenshotUrl = req.body.screenshot;
        }

        const user = await User.findById(userId).select("accountNumber email firstName").lean();

        const tr = new TransferRequest({
            userId,
            accountNumber: (user && user.accountNumber) || "",
            methodId,
            methodSnapshot: { name: method.name, type: method.type, details: method.details, qrImageUrl: method.qrImageUrl },
            amount: Number(amount),
            currency: method.currency || "USD",
            description: description || "",
            screenshot: screenshotUrl,
            status: "pending",
        });

        await tr.save();

        // optional email to admin
        try {
            const adminEmail = process.env.ADMIN_EMAIL;
            if (adminEmail) {
                await sendMail({
                    to: adminEmail,
                    subject: `New top-up/transfer request ${tr._id}`,
                    html: `<p>Request ID: ${tr._id}</p><p>User: ${user && user.accountNumber}</p><p>Amount: ${tr.amount}</p>`,
                });
            }
        } catch (e) { console.warn("admin notify failed", e && e.message); }

        return res.status(201).json({ message: "Request created", request: tr });
    } catch (err) {
        console.error("createTransferRequest", err);
        return res.status(500).json({ message: "Server error" });
    }
}

module.exports = {
    listMethods,
    createMethod,
    updateMethod,
    deleteMethod,
    listTransferRequests,
    actionTransferRequest,
    createTransferRequest,
};
