// backend/models/User.js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    firstName: { type: String, trim: true, required: true },
    lastName: { type: String, trim: true, required: true },
    middleName: { type: String, trim: true },
    username: { type: String, trim: true, required: true, unique: true },
    email: {
      type: String,
      trim: true,
      required: true,
      unique: true,
      lowercase: true,
    },
    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, index: true, sparse: true },
    emailVerificationExpires: { type: Date, default: null },
    phone: { type: String, trim: true, required: true },
    country: { type: String, trim: true, required: true },
    accountType: { type: String, trim: true, default: "checking" },
    accountNumber: { type: String, trim: true, unique: true },
    password: { type: String, required: true },
    pin: { type: String, required: true },
    active: { type: Boolean, default: false },

    // freeze / block fields
    frozen: { type: Boolean, default: false },
    freezeReason: { type: String, default: "" },
    frozenAt: { type: Date, default: null },
    frozenBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // roles
    role: { type: String, enum: ["user", "admin"], default: "user" },
    isAdmin: { type: Boolean, default: false },

    // balances & stats
    balance: { type: Number, default: 0 }, // currency units
    monthlyIncome: { type: Number, default: 0 },
    monthlyOutgoing: { type: Number, default: 0 },

    // optional profile fields
    address: { type: String },
    dob: { type: Date },

    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.pin;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model("User", userSchema);
