// backend/models/Transaction.js
const mongoose = require("mongoose");

const txSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    }, // owner of this tx record
    counterpartyAccount: { type: String }, // other side account number
    counterpartyName: { type: String },
    type: { type: String, enum: ["debit", "credit"], required: true },
    amount: { type: Number, required: true }, // positive value
    fee: { type: Number, default: 0 }, // fee applied (only for debit)
    description: { type: String },
    metadata: { type: Object, default: {} },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Transaction", txSchema);
