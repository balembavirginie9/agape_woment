// backend/server.js
require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const http = require("http");

const userRoutes = require("./routes/user");
const adminRoutes = require("./routes/admin");
const adminPaymentsRoutes = require("./routes/admin_payments");

const app = express();
const PORT = process.env.PORT || 5000;

// Read important envs
const FRONTEND_URL =
  process.env.CORS_ORIGIN ||
  process.env.FRONTEND_URL ||
  "https://rb-digital.diotal.com";
const BASE_URL = process.env.BASE_URL || `https://rb-backend-hgqn.onrender.com`;

// Basic security headers
app.use(helmet());

// Build CSP with dynamic origins (include backend & frontend)
const cspDirectives = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com",
      "https://fonts.googleapis.com",
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com",
      "https://fonts.googleapis.com",
    ],
    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com",
      "https://cdnjs.cloudflare.com",
    ],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", FRONTEND_URL, BASE_URL, "https:"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: ["'none'"],
  },
};
app.use(helmet.contentSecurityPolicy(cspDirectives));

// Middleware
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (e.g. mobile apps, curl)
      if (!origin) return callback(null, true);
      if (origin === FRONTEND_URL) return callback(null, true);
      return callback(new Error("CORS policy: Origin not allowed"), false);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
  }),
);

// Mount API routes
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/admin/payments", adminPaymentsRoutes);

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// Static frontend (optional if present)
const frontendDir = path.join(__dirname, "..", "frontend");
if (fs.existsSync(frontendDir)) {
  app.use(express.static(frontendDir));
  const indexPath = path.join(frontendDir, "index.html");
  if (fs.existsSync(indexPath)) {
    app.get(/^\/(?!api).*/, (req, res) => res.sendFile(indexPath));
  } else {
    app.get(/^\/(?!api).*/, (req, res) =>
      res.status(404).send("Frontend not deployed on this service."),
    );
  }
} else {
  console.warn(
    "frontend folder not present — skipping static serve (hosting separate).",
  );
}

// Connect DB and start server (no socket attach)
const MONGO = process.env.MONGODB_URI;
if (!MONGO) {
  console.error("Missing MONGODB_URI in env.");
  process.exit(1);
}

mongoose.set("strictQuery", false);
mongoose
  .connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("MongoDB connected");

    // start plain HTTP server (no socket.io)
    const server = http.createServer(app);
    server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });
