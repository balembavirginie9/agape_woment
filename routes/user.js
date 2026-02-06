// backend/routes/user.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const router = express.Router();

const User = require("../models/User");
const Transaction = require("../models/Transaction");
const Withdrawal = require("../models/Withdrawal");
const Support = require("../models/Support");
const CardRequest = require("../models/CardRequest"); // replaced old Chat model
const { sendMail } = require("../utils/mail");

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret12345";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "7d";

// multer upload setup
// make sure uploads/topups exists (path relative to repo root)
const uploadRoot = path.join(__dirname, "..", "..", "uploads", "topups");
fs.mkdirSync(uploadRoot, { recursive: true });

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadRoot);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || "";
    const basename = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    cb(null, basename + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: function (req, file, cb) {
    if (!file.mimetype || !file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image uploads are allowed."));
    }
    cb(null, true);
  },
});

// helper: generate 11-digit account number starting with 80
async function generateUniqueAccountNumber() {
  const prefix = "80";
  const maxAttempts = 8;
  for (let i = 0; i < maxAttempts; i++) {
    const rand = Math.floor(Math.random() * 1_000_000_000)
      .toString()
      .padStart(9, "0");
    const candidate = prefix + rand;
    const exists = await User.findOne({ accountNumber: candidate })
      .select("_id")
      .lean();
    if (!exists) return candidate;
  }
  throw new Error("Unable to generate unique account number — try again");
}

// -----------------
// Public routes
// -----------------

// POST /api/users/register
router.post("/register", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      middleName,
      username,
      email,
      phone,
      country,
      accountType,
      pin,
      password,
    } = req.body;
    if (
      !firstName ||
      !lastName ||
      !username ||
      !email ||
      !phone ||
      !country ||
      !pin ||
      !password
    ) {
      return res.status(400).json({ message: "Missing required fields." });
    }
    if (!/^\d{4}$/.test(pin))
      return res.status(400).json({ message: "PIN must be 4 digits." });
    if (password.length < 8)
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters." });

    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail)
      return res.status(409).json({ message: "Email already in use." });
    const existingUsername = await User.findOne({ username });
    if (existingUsername)
      return res.status(409).json({ message: "Username already taken." });

    const accountNumber = await generateUniqueAccountNumber();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);

    const user = new User({
      firstName,
      lastName,
      middleName,
      username,
      email: email.toLowerCase(),
      phone,
      country,
      accountType: accountType || "checking",
      accountNumber,
      password: hashedPassword,
      pin: hashedPin,
      active: false,
      balance: 0,
      role: "user",
      emailVerified: false,
    });

    // generate email verification token
    const token = crypto.randomBytes(20).toString("hex");
    const expiresMs = Number(
      process.env.EMAIL_VERIFICATION_EXPIRES || 24 * 60 * 60 * 1000
    );
    user.emailVerificationToken = token;
    user.emailVerificationExpires = new Date(Date.now() + expiresMs);

    await user.save();

    // send verification email (best-effort)
    try {
      const base = process.env.BASE_URL || "http://localhost:5000";
      const verifyUrl = `${base}/api/users/verify-email?token=${token}`;
      await sendMail({
        to: user.email,
        subject: "Verify your RB-FINANCE email",
        text: `Hello ${user.firstName || ""},\n\nPlease verify your email by visiting: ${verifyUrl}\n\nThis link expires in 24 hours.`,
        html: `<p>Hello ${user.firstName || ""},</p>
               <p>Please verify your email by clicking the link below:</p>
               <p><a href="${verifyUrl}">Verify my email</a></p>
               <p>If you didn't create an account, ignore this message.</p>`,
      });
    } catch (e) {
      console.error("Failed to send verification email", e && e.message);
    }

    const out = user.toJSON ? user.toJSON() : user;
    return res
      .status(201)
      .json({ message: "User registered successfully.", user: out });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error. Check logs." });
  }
});

// POST /api/users/login -> returns { token, user }
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required." });

    const user = await User.findOne({ email: email.toLowerCase() }).lean();
    if (!user) return res.status(401).json({ message: "Invalid credentials." });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: "Invalid credentials." });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES,
    });
    delete user.password;
    delete user.pin;
    delete user.__v;

    return res.status(200).json({ message: "Login successful.", token, user });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// GET /api/users/account/:accountNumber  (public lookup)
router.get("/account/:accountNumber", async (req, res) => {
  try {
    const acc = req.params.accountNumber;
    const user = await User.findOne({ accountNumber: acc })
      .select("firstName lastName accountType accountNumber")
      .lean();
    if (!user) return res.status(404).json({ message: "Account not found" });
    return res.json({ account: user });
  } catch (err) {
    console.error("GET /account/:acct error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// -----------------
// Auth middleware
// -----------------
async function verifyToken(req, res, next) {
  const auth = req.headers.authorization || req.headers.Authorization;
  if (!auth)
    return res.status(401).json({ message: "Missing Authorization header" });
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ message: "Invalid Authorization format" });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;

    // load a small user object for handlers (avoid extra lookup where possible)
    const user = await User.findById(req.userId)
      .select("role accountNumber firstName lastName email isAdmin frozen")
      .lean();
    if (!user) return res.status(401).json({ message: "Invalid token user" });
    req.userIsAdmin = !!(user && (user.role === "admin" || user.isAdmin));
    req.user = user;

    next();
  } catch (err) {
    console.error("verifyToken error:", err && err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ---------------------------
// Protected routes
// ---------------------------

// GET /api/users/me
router.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    delete user.password;
    delete user.pin;
    delete user.__v;
    return res.json({ user });
  } catch (err) {
    console.error("GET /me error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// PATCH /api/users/me  -> update allowed fields
router.patch("/me", verifyToken, async (req, res) => {
  try {
    const allowed = [
      "firstName",
      "lastName",
      "middleName",
      "phone",
      "country",
      "address",
      "dob",
      "username",
    ];
    const updates = {};
    allowed.forEach((k) => {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    });
    if (Object.keys(updates).length === 0)
      return res.status(400).json({ message: "No valid fields to update." });

    if (updates.username) {
      const exists = await User.findOne({
        username: updates.username,
        _id: { $ne: req.userId },
      }).lean();
      if (exists)
        return res.status(409).json({ message: "Username already taken." });
    }

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: updates },
      { new: true, runValidators: true }
    ).lean();
    if (!user) return res.status(404).json({ message: "User not found." });
    delete user.password;
    delete user.pin;
    delete user.__v;
    return res.json({ message: "Profile updated.", user });
  } catch (err) {
    console.error("PATCH /me error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// GET /api/users/me/transactions
router.get("/me/transactions", verifyToken, async (req, res) => {
  try {
    // return up to 50 most recent transactions for this user
    const txs = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    return res.json({ transactions: txs || [] });
  } catch (err) {
    console.error("GET /me/transactions", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// DELETE /api/users/me/transactions/:txId  -> delete single transaction
router.delete("/me/transactions/:txId", verifyToken, async (req, res) => {
  try {
    const txId = req.params.txId;
    const tx = await Transaction.findOne({
      _id: txId,
      userId: req.userId,
    }).exec();
    if (!tx) return res.status(404).json({ message: "Transaction not found" });
    await tx.deleteOne();
    return res.json({ message: "Transaction deleted." });
  } catch (err) {
    console.error("DELETE /me/transactions/:txId", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// DELETE /api/users/me/transactions  -> delete all user's transactions
router.delete("/me/transactions", verifyToken, async (req, res) => {
  try {
    await Transaction.deleteMany({ userId: req.userId });
    return res.json({ message: "All transactions deleted for this user." });
  } catch (err) {
    console.error("DELETE /me/transactions", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/users/me/verify-password
router.post("/me/verify-password", verifyToken, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password)
      return res.status(400).json({ message: "Password required." });
    const user = await User.findById(req.userId).select("password").lean();
    if (!user) return res.status(404).json({ message: "User not found." });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid password." });
    return res.json({ message: "Password verified." });
  } catch (err) {
    console.error("verify-password error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/users/me/change-password
router.post("/me/change-password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res
        .status(400)
        .json({ message: "Provide currentPassword and newPassword." });
    if (newPassword.length < 8)
      return res
        .status(400)
        .json({ message: "New password must be at least 8 characters." });

    const user = await User.findById(req.userId).select("password").exec();
    if (!user) return res.status(404).json({ message: "User not found." });

    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match)
      return res
        .status(401)
        .json({ message: "Current password is incorrect." });

    user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await user.save();
    return res.json({ message: "Password changed successfully." });
  } catch (err) {
    console.error("change-password error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/users/me/transfer
router.post("/me/transfer", verifyToken, async (req, res) => {
  try {
    const senderId = req.userId;
    const { toAccountNumber, amount, description, pin } = req.body;
    if (!toAccountNumber || !amount || !pin)
      return res
        .status(400)
        .json({ message: "toAccountNumber, amount and pin are required." });

    const parsedAmount = Number(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0)
      return res
        .status(400)
        .json({ message: "Amount must be a positive number." });

    // load sender (including hashed pin and frozen state)
    const senderDoc = await User.findById(senderId)
      .select(
        "pin firstName lastName accountNumber balance email frozen freezeReason"
      )
      .exec();
    if (!senderDoc)
      return res.status(404).json({ message: "Sender not found." });

    // block if frozen
    if (senderDoc.frozen) {
      return res.status(403).json({
        message: "Account frozen",
        reason:
          senderDoc.freezeReason ||
          "Your account has been temporarily restricted. Contact support for details.",
      });
    }

    const pinMatch = await bcrypt.compare(String(pin), senderDoc.pin);
    if (!pinMatch) return res.status(401).json({ message: "Invalid PIN." });

    // fee & totals
    const fee = Math.round(parsedAmount * 0.002 * 100) / 100;
    const totalDebit = Math.round((parsedAmount + fee) * 100) / 100;

    // atomically debit sender if sufficient funds
    const sender = await User.findOneAndUpdate(
      { _id: senderId, balance: { $gte: totalDebit } },
      { $inc: { balance: -totalDebit } },
      { new: true }
    ).lean();
    if (!sender)
      return res
        .status(400)
        .json({ message: "Insufficient funds or sender not found." });

    // credit recipient
    const recipient = await User.findOneAndUpdate(
      { accountNumber: toAccountNumber },
      { $inc: { balance: parsedAmount } },
      { new: true }
    ).lean();

    if (!recipient) {
      // rollback sender
      await User.findByIdAndUpdate(senderId, { $inc: { balance: totalDebit } });
      return res
        .status(404)
        .json({ message: "Recipient not found; transaction rolled back." });
    }

    const now = new Date();

    // Friendly descriptions
    const senderName =
      `${sender.firstName || ""} ${sender.lastName || ""}`.trim() || "Sender";
    const recipientName =
      `${recipient.firstName || ""} ${recipient.lastName || ""}`.trim() ||
      "Recipient";
    const senderAccount =
      sender.accountNumber || (sender._id && sender._id.toString());
    const recipientAccount =
      recipient.accountNumber || (recipient._id && recipient._id.toString());

    // Sender transaction - debit
    const senderTx = new Transaction({
      userId: senderId,
      counterpartyAccount: recipientAccount,
      counterpartyName: recipientName,
      type: "debit",
      amount: parsedAmount,
      fee,
      description:
        description ||
        `You sent $${parsedAmount.toFixed(
          2
        )} to ${recipientName} (Account: ${recipientAccount})`,
      createdAt: now,
    });

    // Recipient transaction - credit
    const recipientTx = new Transaction({
      userId: recipient._id,
      counterpartyAccount: senderAccount,
      counterpartyName: senderName,
      type: "credit",
      amount: parsedAmount,
      fee: 0,
      description:
        description ||
        `You received $${parsedAmount.toFixed(
          2
        )} from ${senderName} (Account: ${senderAccount})`,
      createdAt: now,
    });

    await senderTx.save();
    await recipientTx.save();

    // Optionally: send email notifications (best-effort)
    try {
      if (recipient.email) {
        await sendMail({
          to: recipient.email,
          subject: `You received $${parsedAmount.toFixed(2)}`,
          html: `<p>Hi ${recipientName},</p>
                 <p>You received $${parsedAmount.toFixed(
            2
          )} from ${senderName} (Account: ${senderAccount}).</p>
                 <p>Description: ${description || "—"}</p>`,
        });
      }
      if (sender.email) {
        await sendMail({
          to: sender.email,
          subject: `You sent $${parsedAmount.toFixed(2)}`,
          html: `<p>Hi ${senderName},</p>
                 <p>You sent $${parsedAmount.toFixed(
            2
          )} to ${recipientName} (Account: ${recipientAccount}).</p>
                 <p>Description: ${description || "—"}</p>`,
        });
      }
    } catch (mailErr) {
      console.warn(
        "Transfer notification email failed:",
        mailErr && mailErr.message
      );
    }

    // Return fresh sender data
    const updatedSender = await User.findById(senderId)
      .select("-password -pin -__v")
      .lean();
    return res.json({
      message: "Transfer completed successfully.",
      sender: updatedSender,
      recipient: {
        accountNumber: recipient.accountNumber,
        firstName: recipient.firstName,
        lastName: recipient.lastName,
        accountType: recipient.accountType,
      },
      transaction: {
        id: senderTx._id,
        amount: senderTx.amount,
        fee: senderTx.fee,
        createdAt: senderTx.createdAt,
      },
    });
  } catch (err) {
    console.error("Transfer error", err);
    return res.status(500).json({ message: "Server error during transfer." });
  }
});

// POST /api/users/support
router.post("/support", verifyToken, async (req, res) => {
  try {
    const { subject, message, email } = req.body;
    if (!message) return res.status(400).json({ message: "Missing message" });

    const user = await User.findById(req.userId)
      .select("email accountNumber firstName frozen freezeReason frozenAt")
      .lean();
    const contactEmail =
      (email && String(email).trim()) || (user && user.email) || "";

    if (!contactEmail)
      return res.status(400).json({ message: "Email required" });

    const ticket = new Support({
      userId: req.userId || null,
      accountNumber: (user && user.accountNumber) || "",
      email: contactEmail,
      subject: subject || "Support request",
      message,
      freezeInfo: {
        frozen: !!(user && user.frozen),
        freezeReason: (user && user.freezeReason) || "",
        frozenAt: (user && user.frozenAt) || null,
      },
      status: "open",
    });

    await ticket.save();

    // notify admin if configured
    try {
      const adminEmail = process.env.ADMIN_EMAIL;
      if (adminEmail) {
        await sendMail({
          to: adminEmail,
          subject: `New support ticket: ${ticket._id} — ${ticket.subject}`,
          html: `<p>Ticket ID: ${ticket._id}</p>
                 <p>User: ${user ? (user.firstName || "") + " (" + (user.accountNumber || "") + ")" : "N/A"}</p>
                 <p>Email: ${contactEmail}</p>
                 <p>Freeze: ${ticket.freezeInfo.frozen ? "YES" : "NO"}</p>
                 <p>Message:</p><pre>${ticket.message}</pre>`,
        });
      }
    } catch (e) {
      console.warn("Failed to email admin about support ticket", e && e.message);
    }

    return res
      .status(201)
      .json({ message: "Support request received", ticketId: ticket._id });
  } catch (err) {
    console.error("Support err", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/users/me/withdraw
router.post("/me/withdraw", verifyToken, async (req, res) => {
  try {
    const { method, details, amount } = req.body;
    if (!method || !amount)
      return res.status(400).json({ message: "Method and amount required." });
    const parsedAmount = Number(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0)
      return res.status(400).json({ message: "Invalid amount." });

    // check if user is frozen BEFORE debiting
    const who = await User.findById(req.userId)
      .select("balance frozen freezeReason email firstName")
      .exec();
    if (!who) return res.status(404).json({ message: "User not found." });
    if (who.frozen) {
      return res.status(403).json({
        message: "Account frozen",
        reason:
          who.freezeReason ||
          "Your account has been temporarily restricted. Contact support.",
      });
    }

    const fee = 0;
    const totalHold = Math.round((parsedAmount + fee) * 100) / 100;

    const user = await User.findOneAndUpdate(
      { _id: req.userId, balance: { $gte: totalHold } },
      { $inc: { balance: -totalHold } },
      { new: true }
    ).lean();
    if (!user)
      return res
        .status(400)
        .json({ message: "Insufficient funds or user not found." });

    const w = new Withdrawal({
      userId: req.userId,
      accountNumber: user.accountNumber,
      method,
      details: details || {},
      amount: parsedAmount,
      fee,
      status: "pending",
    });
    await w.save();

    // send confirmation email to user (best-effort)
    try {
      await sendMail({
        to: user.email,
        subject: "Withdrawal request received",
        html: `<p>Hi ${user.firstName || ""},</p>
               <p>We received your withdrawal request for ${parsedAmount.toFixed(
          2
        )} via ${method}.</p>
               <p>Request ID: ${w._id}. Status: ${w.status}</p>
               <p>We will notify you when it is processed.</p>`,
      });
    } catch (e) {
      console.error("Failed to send withdrawal email", e && e.message);
    }

    return res.json({
      message: "Withdrawal request created and sent for review.",
      withdrawal: w,
      user,
    });
  } catch (err) {
    console.error("POST /me/withdraw error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Admin helper: fetch transactions for a given user id
router.get("/by-id/:id/transactions", verifyToken, async (req, res) => {
  try {
    const requestedId = req.params.id;
    if (req.userId !== requestedId && !req.userIsAdmin)
      return res.status(403).json({ message: "Forbidden" });

    const txs = await Transaction.find({ userId: requestedId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();
    return res.json({ transactions: txs });
  } catch (err) {
    console.error("GET /by-id/:id/transactions", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Card request endpoints (use CardRequest model)
router.post("/me/card-request", verifyToken, async (req, res) => {
  try {
    const { cardType, level, currency, dailyLimit } = req.body;
    if (!cardType || !level)
      return res.status(400).json({ message: "Missing fields" });

    const me = await User.findById(req.userId).lean();
    if (!me) return res.status(404).json({ message: "User not found" });

    const cr = new CardRequest({
      userId: req.userId,
      accountNumber: me.accountNumber,
      firstName: me.firstName,
      lastName: me.lastName,
      cardType,
      level,
      currency,
      dailyLimit: Number(dailyLimit || 0),
      status: "pending",
    });
    await cr.save();
    return res
      .status(201)
      .json({ message: "Card request created", request: cr });
  } catch (err) {
    console.error("card-request error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/me/card-requests", verifyToken, async (req, res) => {
  try {
    const requests = await CardRequest.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .lean();
    return res.json({ requests });
  } catch (err) {
    console.error("GET me card-requests", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// GET /api/users/me/cards — show approved card requests as "cards"
router.get("/me/cards", verifyToken, async (req, res) => {
  try {
    const approved = await CardRequest.find({
      userId: req.userId,
      status: "approved",
    })
      .lean()
      .catch((err) => {
        console.warn("[cards] CardRequest.find failed:", err && err.message);
        return [];
      });
    const mapped = (approved || []).map((c) => ({
      _id: c._id,
      brand: c.cardType || "Virtual Card",
      maskedNumber:
        c.maskedNumber ||
        "•••• •••• •••• " + Math.floor(1000 + Math.random() * 8999),
      level: c.level || "Standard",
      expiry: c.expiry || "12/25",
      balance: c.balance || 0,
      status: "active",
    }));
    return res.json({ cards: mapped });
  } catch (err) {
    console.error("GET /me/cards error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// GET /api/users/verify-email?token=...
router.get("/verify-email", async (req, res) => {
  try {
    const token = (req.query.token || "").toString();
    if (!token) return res.status(400).send("Missing token");

    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).send("Invalid or expired verification token");
    }

    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    const frontendUrl =
      (process.env.FRONTEND_URL || process.env.BASE_URL) + "/login.html?verified=1";
    return res.redirect(frontendUrl);
  } catch (err) {
    console.error("verify-email error", err);
    return res.status(500).send("Server error");
  }
});

// POST /api/users/resend-verification
router.post("/resend-verification", async (req, res) => {
  try {
    const email = (req.body.email || "").toString().toLowerCase();
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "Not found" });
    if (user.emailVerified)
      return res.status(400).json({ message: "Already verified" });

    const token = crypto.randomBytes(20).toString("hex");
    const expiresMs = Number(
      process.env.EMAIL_VERIFICATION_EXPIRES || 24 * 60 * 60 * 1000
    );
    user.emailVerificationToken = token;
    user.emailVerificationExpires = new Date(Date.now() + expiresMs);
    await user.save();

    const base = process.env.BASE_URL || "";
    const verifyUrl = `${base}/api/users/verify-email?token=${token}`;

    await sendMail({
      to: user.email,
      subject: "Your RB-FINANCE email verification",
      text: `Verify your email: ${verifyUrl}`,
      html: `<p>Verify your email: <a href="${verifyUrl}">Verify</a></p>`,
    });

    return res.json({ message: "Verification email sent" });
  } catch (err) {
    console.error("resend-verification error", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/users/me/topup (upload screenshot)
router.post(
  "/me/topup",
  verifyToken,
  upload.single("screenshot"),
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);
      const walletAddress = (req.body.walletAddress || "").toString();

      if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ message: "Invalid amount" });
      }
      if (!req.file) {
        return res.status(400).json({ message: "Screenshot file is required" });
      }

      // URL we can store in metadata (served from /uploads)
      const screenshotUrl = `/uploads/topups/${req.file.filename}`;

      // create a pending top-up transaction record
      const tx = new Transaction({
        userId: req.userId,
        counterpartyAccount: walletAddress || "BTC",
        counterpartyName: "BTC Top-up",
        type: "credit",
        amount: Number(amount),
        fee: 0,
        description: "Top-up via Bitcoin (pending verification)",
        metadata: { screenshot: screenshotUrl, pending: true },
      });

      await tx.save();

      return res.status(201).json({
        message:
          "Top-up request received. It will be reviewed and verified by admin.",
        transaction: tx,
      });
    } catch (err) {
      console.error("POST /me/topup error", (err && err.stack) || err);
      // multer fileFilter errors bubble here as plain Error; return 400 for those
      if (err && err.message && err.message.includes("Only image uploads")) {
        return res.status(400).json({ message: err.message });
      }
      return res.status(500).json({ message: "Internal server error" });
    }
  }
);

module.exports = router;
