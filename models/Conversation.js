// backend/models/Conversation.js
const mongoose = require("mongoose");

const conversationSchema = new mongoose.Schema(
  {
    // The non-admin user who owns this conversation
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    userName: String,
    accountNumber: String,
    participants: [{ type: String }], // e.g. ['admin','user']
    lastMessage: {
      text: String,
      from: String,
      createdAt: Date,
    },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Conversation", conversationSchema);
