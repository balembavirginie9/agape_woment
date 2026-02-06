// backend/models/Support.js
const mongoose = require("mongoose");

const supportSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false,
    },
    accountNumber: { type: String, default: "" },
    email: { type: String, required: true },
    subject: { type: String, default: "Support request" },
    message: { type: String, required: true },
    freezeInfo: {
      frozen: { type: Boolean, default: false },
      freezeReason: { type: String, default: "" },
      frozenAt: { type: Date, default: null },
    },
    status: { type: String, enum: ["open", "resolved"], default: "open" },
    processedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    processedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Support", supportSchema);
