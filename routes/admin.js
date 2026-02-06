// backend/routes/admin.js
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Withdrawal = require("../models/Withdrawal");
const Transaction = require("../models/Transaction");
const Support = require("../models/Support");
const { sendMail } = require("../utils/mail");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret12345";

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

    // load small user object for authorization checks
    const user = await User.findById(req.userId)
      .select("isAdmin role email firstName lastName")
      .lean();
    if (!user) return res.status(401).json({ message: "Invalid token user" });
    req.user = user;
    req.userIsAdmin = !!(user.isAdmin || user.role === "admin");
    next();
  } catch (err) {
    console.error("verifyToken error:", err && err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || !(req.user.isAdmin || req.user.role === "admin"))
    return res.status(403).json({ message: "Admin required" });
  return next();
}

router.get("/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(
      200,
      Math.max(10, parseInt(req.query.pageSize || "50", 10))
    );
    const skip = (page - 1) * pageSize;
    const [total, users] = await Promise.all([
      User.countDocuments({}),
      User.find({})
        .select("-password -pin -__v")
        .skip(skip)
        .limit(pageSize)
        .sort({ createdAt: -1 })
        .lean(),
    ]);
    return res.json({ total, page, pageSize, users });
  } catch (err) {
    console.error("GET admin/users", err);
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/users/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id).select("-password -pin -__v").lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json({ user });
  } catch (err) {
    console.error("GET admin/users/:id", err);
    return res.status(500).json({ message: "Server error" });
  }
});

router.delete("/users/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findByIdAndDelete(id).lean();
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.json({ message: "User deleted", userId: id });
  } catch (err) {
    console.error("DELETE admin/users", err);
    return res.status(500).json({ message: "Server error" });
  }
});

router.patch("/users/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const allowed = [
      "firstName",
      "lastName",
      "middleName",
      "phone",
      "country",
      "address",
      "dob",
      "username",
      "active",
      "accountType",
    ];
    const updates = {};
    allowed.forEach((k) => {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    });

    const balanceAdjustment =
      req.body.balanceAdjustment !== undefined
        ? Number(req.body.balanceAdjustment)
        : undefined;
    const balanceNote = req.body.balanceNote || "";

    let user = await User.findById(id).exec();
    if (!user) return res.status(404).json({ message: "User not found" });

    Object.assign(user, updates);

    if (!isNaN(balanceAdjustment) && balanceAdjustment !== 0) {
      user.balance = (user.balance || 0) + balanceAdjustment;
      try {
        const tx = new Transaction({
          userId: user._id,
          counterpartyAccount: "ADMIN",
          counterpartyName: "Admin Adjustment",
          type: balanceAdjustment < 0 ? "debit" : "credit",
          amount: Math.abs(balanceAdjustment),
          fee: 0,
          description: `Admin balance adjustment: ${balanceNote}`,
        });
        await tx.save();
      } catch (e) {
        console.warn("Failed to create adjustment transaction", e);
      }

      try {
        if (user.email) {
          const verb = balanceAdjustment < 0 ? "debited" : "credited";
          await sendMail({
            to: user.email,
            subject: `Account ${verb} by admin`,
            html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your account was ${verb} by $${Math.abs(
              balanceAdjustment
            ).toFixed(2)}.</p>
                   <p>Note: ${balanceNote || "Admin adjustment"}</p>`,
          });
        }
      } catch (e) {
        console.error(
          "Failed to send balance adjustment email",
          e && e.message
        );
      }
    }

    await user.save();
    const out = user.toObject();
    delete out.password;
    delete out.pin;
    delete out.__v;
    return res.json({ message: "User updated", user: out });
  } catch (err) {
    console.error("PATCH admin/users/:id", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/users/:id/freeze
 */
router.post(
  "/users/:id/freeze",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const reason = (req.body.reason || "").toString();
      const user = await User.findByIdAndUpdate(
        id,
        {
          $set: {
            frozen: true,
            freezeReason: reason,
            frozenAt: new Date(),
            frozenBy: req.userId,
          },
        },
        { new: true }
      )
        .select("-password -pin -__v")
        .lean();
      if (!user) return res.status(404).json({ message: "User not found" });

      try {
        if (user.email) {
          await sendMail({
            to: user.email,
            subject: "Your account has been frozen",
            html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your account has been temporarily frozen by admin.</p>
                   <p>Reason: ${reason || "No reason provided"}</p>
                   <p>If you believe this is an error, contact support.</p>`,
          });
        }
      } catch (e) {
        console.warn("Failed to email user about freeze:", e && e.message);
      }

      return res.json({ message: "User frozen", user });
    } catch (err) {
      console.error("POST admin/users/:id/freeze", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

/**
 * POST /api/admin/users/:id/unfreeze
 */
router.post(
  "/users/:id/unfreeze",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const note = (req.body.note || "").toString();
      const user = await User.findByIdAndUpdate(
        id,
        {
          $set: {
            frozen: false,
            freezeReason: "",
            frozenAt: null,
            frozenBy: null,
          },
        },
        { new: true }
      )
        .select("-password -pin -__v")
        .lean();
      if (!user) return res.status(404).json({ message: "User not found" });

      try {
        if (user.email) {
          await sendMail({
            to: user.email,
            subject: "Your account has been unfrozen",
            html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your account has been restored to normal.</p>
                   <p>${note ? "Note: " + note : ""}</p>`,
          });
        }
      } catch (e) {
        console.warn("Failed to email user about unfreeze", e && e.message);
      }

      return res.json({ message: "User unfrozen", user });
    } catch (err) {
      console.error("POST admin/users/:id/unfreeze", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

/**
 * GET /api/admin/withdrawals
 */
router.get("/withdrawals", verifyToken, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || "pending";
    const q = status === "all" ? {} : { status };
    const withdrawals = await Withdrawal.find(q)
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();
    return res.json({ withdrawals });
  } catch (err) {
    console.error("GET admin/withdrawals", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/withdrawals/:id/action
 */
router.post(
  "/withdrawals/:id/action",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const wid = req.params.id;
      const { action, message } = req.body;
      if (!["approve", "decline", "investigation"].includes(action))
        return res.status(400).json({ message: "Invalid action" });

      const w = await Withdrawal.findById(wid);
      if (!w) return res.status(404).json({ message: "Withdrawal not found" });

      const user = await User.findById(w.userId)
        .select("email firstName lastName accountNumber")
        .lean();

      if (action === "decline") {
        if (w.status !== "pending")
          return res
            .status(400)
            .json({ message: "Cannot decline non-pending withdrawal" });
        if (user) {
          await User.findByIdAndUpdate(user._id, {
            $inc: { balance: w.amount + (w.fee || 0) },
          });
        }
        w.status = "declined";
        w.adminMessage = message || "Declined by admin";
        w.processedBy = req.userId;
        w.processedAt = new Date();
        await w.save();

        try {
          if (user && user.email) {
            await sendMail({
              to: user.email,
              subject: "Withdrawal declined",
              html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your withdrawal request (${w._id}) has been declined.</p>
                   <p>Message: ${w.adminMessage}</p>`,
            });
          }
        } catch (e) {
          console.error(
            "Failed to send withdrawal-declined email",
            e && e.message
          );
        }

        return res.json({
          message: "Withdrawal declined and refunded",
          withdrawal: w,
        });
      }

      if (action === "investigation") {
        w.status = "investigation";
        w.adminMessage = message || "Marked for investigation";
        w.processedBy = req.userId;
        w.processedAt = new Date();
        await w.save();

        try {
          if (user && user.email) {
            await sendMail({
              to: user.email,
              subject: "Withdrawal under investigation",
              html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your withdrawal request (${w._id
                }) has been flagged for investigation by our team. Message: ${w.adminMessage
                }</p>`,
            });
          }
        } catch (e) {
          console.error(
            "Failed to send withdrawal-investigation email",
            e && e.message
          );
        }

        return res.json({
          message: "Withdrawal marked for investigation",
          withdrawal: w,
        });
      }

      if (action === "approve") {
        w.status = "approved";
        w.adminMessage = message || "Approved and processed";
        w.processedBy = req.userId;
        w.processedAt = new Date();
        await w.save();

        try {
          if (user && user.email) {
            await sendMail({
              to: user.email,
              subject: "Withdrawal approved",
              html: `<p>Hi ${user.firstName || ""},</p>
                   <p>Your withdrawal request (${w._id
                }) has been approved and processed.</p>`,
            });
          }
        } catch (e) {
          console.error(
            "Failed to send withdrawal-approved email",
            e && e.message
          );
        }

        return res.json({ message: "Withdrawal approved", withdrawal: w });
      }

      return res.json({ message: "Action completed", withdrawal: w });
    } catch (err) {
      console.error("POST admin/withdrawals/:id/action", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

/**
 * GET /api/admin/card-requests
 */
router.get("/card-requests", verifyToken, requireAdmin, async (req, res) => {
  try {
    const list = await CardRequest.find({})
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();
    return res.json({ requests: list });
  } catch (err) {
    console.error("GET admin/card-requests", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/card-requests/:id/action
 */
router.post(
  "/card-requests/:id/action",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const { action, message } = req.body;
      const cr = await CardRequest.findById(id);
      if (!cr) return res.status(404).json({ message: "Request not found" });
      if (!["approve", "decline", "investigation"].includes(action))
        return res.status(400).json({ message: "Invalid action" });

      cr.status =
        action === "approve"
          ? "approved"
          : action === "decline"
            ? "declined"
            : "investigation";
      cr.adminMessage = message || "";
      cr.processedAt = new Date();
      cr.processedBy = req.userId;
      await cr.save();

      try {
        const u = await User.findById(cr.userId)
          .select("email firstName")
          .lean();
        if (u && u.email) {
          const subj =
            action === "approve"
              ? "Card request approved"
              : action === "decline"
                ? "Card request declined"
                : "Card request under review";
          const body = `<p>Hi ${u.firstName || ""},</p><p>Your card request (${cr._id
            }) status changed to ${cr.status}.</p><p>${cr.adminMessage || ""
            }</p>`;
          await sendMail({ to: u.email, subject: subj, html: body });
        }
      } catch (e) {
        console.error(
          "Failed to send card-request notification",
          e && e.message
        );
      }

      return res.json({ message: "Action applied", request: cr });
    } catch (err) {
      console.error("POST admin/card-requests action", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

/**
 * GET /api/admin/supports?status=open|resolved|all
 */
router.get("/supports", verifyToken, requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || "open";
    const q = status === "all" ? {} : { status };
    console.info(`[admin.supports] admin=${req.userId} status=${status}`);
    const supports = await Support.find(q)
      .sort({ createdAt: -1 })
      .limit(500)
      .lean();
    console.info(`[admin.supports] found=${supports.length}`);
    return res.json({ supports });
  } catch (err) {
    console.error("GET admin/supports", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * GET /api/admin/supports/:id
 * Fetch single support ticket detail
 */
router.get("/supports/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const sup = await Support.findById(id).lean();
    if (!sup)
      return res.status(404).json({ message: "Support ticket not found" });
    return res.json({ support: sup });
  } catch (err) {
    console.error("GET admin/supports/:id", err);
    return res.status(500).json({ message: "Server error" });
  }
});

router.post(
  "/supports/:id/resolve",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const note = req.body.note || "";
      const sup = await Support.findByIdAndUpdate(
        id,
        {
          $set: {
            status: "resolved",
            processedBy: req.userId,
            processedAt: new Date(),
            adminNote: note,
          },
        },
        { new: true }
      ).lean();
      if (!sup)
        return res.status(404).json({ message: "Support ticket not found" });

      try {
        if (sup.email) {
          await sendMail({
            to: sup.email,
            subject: `Your support request ${sup._id} has been processed`,
            html: `<p>Hi,</p><p>Your support request (ID: ${sup._id
              }) has been marked resolved by our team.</p><p>${note ? "Note: " + note : ""
              }</p>`,
          });
        }
      } catch (e) {
        console.warn(
          "Failed to email user about support resolution",
          e && e.message
        );
      }

      return res.json({ message: "Ticket marked resolved", ticket: sup });
    } catch (err) {
      console.error("POST admin/supports/:id/resolve", err);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

module.exports = router;
