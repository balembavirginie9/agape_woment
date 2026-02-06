// backend/models/CardRequest.js
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const CardRequestSchema = new Schema(
    {
        userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
        accountNumber: { type: String },
        firstName: { type: String },
        lastName: { type: String },
        cardType: { type: String },
        level: { type: String },
        currency: { type: String },
        dailyLimit: { type: Number, default: 0 },
        status: { type: String, default: "pending" }, // pending|approved|declined|investigation
        maskedNumber: { type: String },
        expiry: { type: String },
        balance: { type: Number, default: 0 },
        adminMessage: { type: String },
        processedBy: { type: Schema.Types.ObjectId, ref: "User" },
        processedAt: { type: Date },
    },
    { timestamps: true }
);

module.exports = mongoose.model("CardRequest", CardRequestSchema);
