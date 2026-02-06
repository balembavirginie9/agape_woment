// backend/routes/user.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const router = express.Router();

const User = require("../models/User");
const { sendMail } = require("../utils/mail");

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret12345";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "7d";

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

// helper: generate username candidate and ensure uniqueness
async function makeUniqueUsername(base) {
  base = (base || "user")
    .toString()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "");
  if (base.length < 3) base = base + Math.floor(100 + Math.random() * 900);
  let username = base;
  let suffix = 0;
  while (true) {
    const exists = await User.findOne({ username }).select("_id").lean();
    if (!exists) return username;
    suffix++;
    username = `${base}${suffix}`;
    if (suffix > 500) throw new Error("Unable to create unique username");
  }
}

// -----------------
// Public routes
// -----------------

// POST /api/users/register
// Accepts either firstName + lastName OR fullname; accepts tel as alias for phone.
router.post("/register", async (req, res) => {
  try {
    let {
      firstName,
      lastName,
      middleName,
      username,
      email,
      phone,
      tel, // alias from form
      country,
      accountType,
      pin,
      password,
      fullname,
      dob,
      gender,
    } = req.body || {};

    // prefer tel over phone
    if (!phone && tel) phone = tel;

    // If fullname provided, split into first/last
    if ((!firstName || !lastName) && fullname) {
      const parts = String(fullname || "")
        .trim()
        .split(/\s+/);
      if (parts.length === 1) {
        firstName = parts[0];
        lastName = parts[0];
      } else if (parts.length >= 2) {
        firstName = parts.shift();
        lastName = parts.join(" ");
      }
    }

    // Create username if not provided
    if (!username) {
      if (email && typeof email === "string" && email.includes("@")) {
        username = email
          .split("@")[0]
          .replace(/[^a-zA-Z0-9._-]/g, "")
          .toLowerCase();
      } else if (firstName) {
        username = (
          firstName + (lastName ? "." + lastName.split(" ").shift() : "")
        )
          .toLowerCase()
          .replace(/[^a-z0-9._-]/g, "");
      } else {
        username = "user" + Math.floor(100 + Math.random() * 900);
      }
      username = await makeUniqueUsername(username);
    } else {
      const existsU = await User.findOne({ username }).select("_id").lean();
      if (existsU)
        return res.status(409).json({ message: "Username already taken." });
    }

    // Basic required checks
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

    if (!/^\d{4}$/.test(String(pin)))
      return res.status(400).json({ message: "PIN must be 4 digits." });
    if (String(password).length < 8)
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters." });

    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail)
      return res.status(409).json({ message: "Email already in use." });

    const accountNumber = await generateUniqueAccountNumber();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const hashedPin = await bcrypt.hash(String(pin), SALT_ROUNDS);

    const userObj = {
      firstName,
      lastName,
      middleName: middleName || "",
      username,
      email: email.toLowerCase(),
      phone,
      country,
      accountType: accountType || "checking",
      accountNumber,
      password: hashedPassword,
      pin: hashedPin,
      active: false,
      role: "user",
      emailVerified: false,
    };

    if (dob) {
      const parsed = new Date(dob);
      if (!Number.isNaN(parsed.getTime())) userObj.dob = parsed;
    }
    if (gender) userObj.gender = gender;

    const user = new User(userObj);

    // email verification token
    const token = crypto.randomBytes(20).toString("hex");
    const expiresMs = Number(
      process.env.EMAIL_VERIFICATION_EXPIRES || 24 * 60 * 60 * 1000,
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
        subject: "Verify your email",
        text: `Hello ${user.firstName || ""},\n\nVerify here: ${verifyUrl}\n\nThis link expires in 24 hours.`,
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

// GET /api/users/account/:accountNumber (optional public lookup)
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
      (process.env.FRONTEND_URL || process.env.BASE_URL) +
      "/login.html?verified=1";
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
      process.env.EMAIL_VERIFICATION_EXPIRES || 24 * 60 * 60 * 1000,
    );
    user.emailVerificationToken = token;
    user.emailVerificationExpires = new Date(Date.now() + expiresMs);
    await user.save();

    const base = process.env.BASE_URL || "";
    const verifyUrl = `${base}/api/users/verify-email?token=${token}`;

    try {
      await sendMail({
        to: user.email,
        subject: "Your email verification",
        text: `Verify your email: ${verifyUrl}`,
        html: `<p>Verify your email: <a href="${verifyUrl}">Verify</a></p>`,
      });
    } catch (e) {
      console.error("Failed to send verification email", e && e.message);
    }

    return res.json({ message: "Verification email sent" });
  } catch (err) {
    console.error("resend-verification error", err);
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
// Protected routes (profile & auth)
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
      { new: true, runValidators: true },
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

module.exports = router;
