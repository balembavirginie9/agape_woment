// backend/models/PaymentMethod.js
const mongoose = require("mongoose");
const { Schema } = mongoose;

const PaymentMethodSchema = new Schema({
    name: { type: String, required: true },
    type: { type: String, required: true }, // e.g. 'btc', 'bank', 'paypal', 'cashapp', 'mobile'
    details: { type: Schema.Types.Mixed, default: {} },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

PaymentMethodSchema.pre("save", function (next) {
    this.updatedAt = new Date();
    next();
});

module.exports = mongoose.model("PaymentMethod", PaymentMethodSchema);
