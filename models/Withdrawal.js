// backend/models/Withdrawal.js
const mongoose = require("mongoose");

const withdrawalSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    accountNumber: { type: String }, // user's account number
    method: { type: String, required: true },
    details: { type: Object, default: {} },
    amount: { type: Number, required: true },
    fee: { type: Number, default: 0 },
    status: {
      type: String,
      enum: ["pending", "approved", "declined", "investigation"],
      default: "pending",
    },
    adminMessage: { type: String, default: "" },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    processedAt: { type: Date },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Withdrawal", withdrawalSchema);
