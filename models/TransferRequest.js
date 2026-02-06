// backend/models/TransferRequest.js
const mongoose = require("mongoose");
const { Schema } = mongoose;

const TransferRequestSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    accountNumber: { type: String, default: "" }, // snapshot
    methodId: { type: Schema.Types.ObjectId, ref: "PaymentMethod" },
    methodSnapshot: { type: Schema.Types.Mixed }, // copy of method at request time (name/type/details)
    amount: { type: Number, required: true },
    currency: { type: String, default: "USD" },
    description: { type: String, default: "" },
    screenshot: { type: String, default: "" }, // stores file path or URL
    status: { type: String, enum: ["pending", "approved", "declined", "investigation"], default: "pending" },
    adminMessage: { type: String, default: "" },
    processedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    processedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model("TransferRequest", TransferRequestSchema);
