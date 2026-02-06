// backend/utils/mail.js
// Uses Resend if RESEND_API_KEY is provided, otherwise falls back to Nodemailer (SMTP).
// Exports: sendMail(options) -> Promise<{ ok: boolean, id?: string, info?: any, error?: any }>

const util = require("util");
const nodemailer = require("nodemailer");

let resendClient = null;
let usingResend = false;

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = process.env.SMTP_PORT
  ? Number(process.env.SMTP_PORT)
  : undefined;
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const EMAIL_FROM =
  process.env.EMAIL_FROM ||
  process.env.FROM_EMAIL ||
  "RB-FINANCE <no-reply@rb-fintech.com>";
const DEFAULT_REPLY_TO = process.env.EMAIL_REPLY_TO || "";

try {
  if (RESEND_API_KEY) {
    // lazy require so local dev without package still works
    const { Resend } = require("resend");
    resendClient = new Resend(RESEND_API_KEY);
    usingResend = true;
    console.info("Mail: using Resend as email provider");
  } else {
    console.info(
      "Mail: RESEND_API_KEY not set; will use SMTP fallback if configured"
    );
  }
} catch (e) {
  console.warn("Mail: Resend SDK not available:", e && e.message);
  usingResend = false;
}

let smtpTransport = null;
async function getSmtpTransport() {
  if (smtpTransport) return smtpTransport;
  if (!SMTP_HOST || !SMTP_PORT) {
    return null;
  }
  smtpTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT || 587,
    secure: SMTP_PORT === 465, // true for 465, false for other ports
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });

  // verify connection (optional but helpful at startup)
  try {
    const verify = util.promisify(smtpTransport.verify).bind(smtpTransport);
    await verify();
    console.info("Mail: SMTP transport verified");
  } catch (err) {
    console.warn("Mail: SMTP verify failed:", err && err.message);
  }

  return smtpTransport;
}

/**
 * sendMail(options)
 * options: {
 *   to: string | string[],
 *   subject: string,
 *   html?: string,
 *   text?: string,
 *   from?: string,          // default EMAIL_FROM
 *   replyTo?: string,
 *   templateId?: string,    // optional Resend template id
 *   templateVars?: object,  // optional template variables for Resend
 *   bcc?: string | string[],
 *   cc?: string | string[],
 *   headers?: object,
 *   attachments?: [{ filename, content (Buffer|string), path, contentType }]
 * }
 */
async function sendMail(opts = {}) {
  const {
    to,
    subject,
    html,
    text,
    from,
    replyTo,
    templateId,
    templateVars,
    bcc,
    cc,
    headers,
    attachments,
  } = opts;

  if (!to) {
    throw new Error("sendMail missing 'to' address");
  }
  if (!subject && !templateId) {
    throw new Error("sendMail requires 'subject' unless sending a template");
  }

  const fromAddr = from || EMAIL_FROM;

  // Use Resend if configured
  if (usingResend && resendClient) {
    try {
      const payload = {
        from: fromAddr,
        to: Array.isArray(to) ? to : [to],
        subject: subject || "",
      };

      if (replyTo || DEFAULT_REPLY_TO)
        payload.replyTo = replyTo || DEFAULT_REPLY_TO;
      if (bcc) payload.bcc = Array.isArray(bcc) ? bcc : [bcc];
      if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];
      if (headers) payload.headers = headers;

      if (templateId) {
        payload.template = { id: templateId, variables: templateVars || {} };
      } else {
        if (html) payload.html = html;
        if (text) payload.text = text;
      }

      if (attachments && Array.isArray(attachments) && attachments.length) {
        // Resend supports attachments: { filename, content } where content is base64 or buffer
        payload.attachments = attachments.map((a) => {
          const item = {};
          if (a.filename) item.filename = a.filename;
          if (a.path) item.path = a.path;
          if (a.content) item.content = a.content; // Buffer or base64 string
          if (a.contentType) item.contentType = a.contentType;
          return item;
        });
      }

      const { data, error } = await resendClient.emails.send(payload);
      if (error) {
        console.error("Mail(Resend) error:", error);
        return { ok: false, error };
      }
      // Resend returns data with id
      return { ok: true, id: data && data.id, info: data };
    } catch (err) {
      console.error(
        "Mail(Resend) unexpected error:",
        err && err.stack ? err.stack : err
      );
      // fallthrough to try SMTP fallback if available
    }
  }

  // Fallback to SMTP via Nodemailer if configured
  const transporter = await getSmtpTransport();
  if (!transporter) {
    const msg =
      "No email provider configured (RESEND_API_KEY and SMTP settings missing or invalid)";
    console.error("Mail error:", msg);
    return { ok: false, error: msg };
  }

  const mailOptions = {
    from: fromAddr,
    to,
    subject: subject || "(no subject)",
    html: html || undefined,
    text: text || undefined,
    replyTo: replyTo || undefined,
    bcc: bcc || undefined,
    cc: cc || undefined,
    headers: headers || undefined,
    attachments: attachments || undefined,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    // info may contain messageId, accepted, rejected, etc.
    return { ok: true, info };
  } catch (err) {
    console.error(
      "Mail(Nodemailer) send error:",
      err && err.stack ? err.stack : err
    );
    return { ok: false, error: err };
  }
}

module.exports = {
  sendMail,
  _internal: { usingResend, getSmtpTransport },
};
