"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://aerovistaanalytics.com";
const PUBLIC_CONTACT_EMAIL = process.env.PUBLIC_CONTACT_EMAIL || "contact@aerovistaanalytics.com";
const CONTACT_TO_EMAIL = process.env.CONTACT_TO_EMAIL || "contact@aerovistaanalytics.com";
const CONTACT_FROM_EMAIL = process.env.CONTACT_FROM_EMAIL || "AeroVista Analytics <contact@aerovistaanalytics.com>";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const ROOT = __dirname;
const MAX_BODY_BYTES = 24 * 1024;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT = 6;
const MAX_RATE_BUCKETS = 10000;
const csrfSecret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString("hex");
const requestCounts = new Map();
let lastRateLimitCleanup = Date.now();
const csrfCookieSecure = PUBLIC_SITE_URL.startsWith("https://") ? "; Secure" : "";

const allowedServices = new Set([
  "Data Analysis & Reporting",
  "Business Intelligence & Dashboards",
  "Data Migration & Consolidation",
  "Process & Performance Analysis",
  "Data Cleaning & Validation",
  "Custom Reports & Automation",
  "Not sure yet",
]);

const allowedTimelines = new Set(["Flexible", "ASAP", "2-4 weeks", "1-3 months", "3+ months"]);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function normalizeHostname(hostname = "") {
  return String(hostname).trim().toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "");
}

function hostnameFromUrl(value) {
  try {
    return normalizeHostname(new URL(value).hostname);
  } catch {
    return "";
  }
}

function hostnameFromHostHeader(value = "") {
  const host = String(value).trim().toLowerCase();
  if (!host) return "";
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end === -1 ? "" : normalizeHostname(host.slice(1, end));
  }
  return normalizeHostname(host.split(":")[0]);
}

const configuredAllowedHosts = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map(normalizeHostname)
  .filter(Boolean);

const allowedHosts = new Set(
  [
    hostnameFromUrl(PUBLIC_SITE_URL),
    "aerovistaanalytics.com",
    "www.aerovistaanalytics.com",
    "aerovista-analytics.onrender.com",
    "localhost",
    "127.0.0.1",
    "::1",
    ...configuredAllowedHosts,
  ].filter(Boolean)
);

function securityHeaders(contentType = "text/plain; charset=utf-8") {
  return {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "X-DNS-Prefetch-Control": "off",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self' 'sha256-p2VFFReR6VdO+dGUJSmz9Oc1qPqi/Xh+TRpHprgboX4='",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  };
}

function sendText(res, status, message) {
  res.writeHead(status, {
    ...securityHeaders(),
    "Cache-Control": "no-store",
  });
  res.end(message);
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    ...securityHeaders("application/json; charset=utf-8"),
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function isAllowedHost(req) {
  return allowedHosts.has(hostnameFromHostHeader(req.headers.host || ""));
}

function isAllowedOrigin(originHeader) {
  if (!originHeader) return true;
  return allowedHosts.has(hostnameFromUrl(originHeader));
}

function parseCookies(cookieHeader = "") {
  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map((cookie) => cookie.trim().split("="))
      .filter(([key, value]) => key && value)
      .map(([key, value]) => [key, decodeURIComponent(value)])
  );
}

function signToken(token) {
  return crypto.createHmac("sha256", csrfSecret).update(token).digest("hex");
}

function createCsrfToken() {
  const token = crypto.randomBytes(24).toString("hex");
  return `${token}.${signToken(token)}`;
}

function isValidCsrfToken(token) {
  if (!token || !token.includes(".")) return false;
  const [raw, signature] = token.split(".");
  const expected = signToken(raw);
  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function rateLimit(req) {
  const ip = getClientIp(req);
  const now = Date.now();

  if (now - lastRateLimitCleanup > RATE_WINDOW_MS || requestCounts.size > MAX_RATE_BUCKETS) {
    for (const [key, timestamps] of requestCounts.entries()) {
      const recent = timestamps.filter((timestamp) => now - timestamp < RATE_WINDOW_MS);
      if (recent.length) {
        requestCounts.set(key, recent);
      } else {
        requestCounts.delete(key);
      }
    }
    lastRateLimitCleanup = now;
  }

  const bucket = requestCounts.get(ip) || [];
  const recent = bucket.filter((timestamp) => now - timestamp < RATE_WINDOW_MS);
  recent.push(now);
  requestCounts.set(ip, recent);
  return recent.length <= RATE_LIMIT;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let body = "";

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body too large."), { status: 413 }));
        req.destroy();
        return;
      }
      body += chunk.toString("utf8");
    });

    req.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(Object.assign(new Error("Invalid JSON body."), { status: 400 }));
      }
    });

    req.on("error", reject);
  });
}

function clean(value, maxLength) {
  return String(value || "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function validateInquiry(payload) {
  const inquiry = {
    requestType: clean(payload.requestType, 40),
    name: clean(payload.name, 100),
    email: clean(payload.email, 160).toLowerCase(),
    company: clean(payload.company, 120),
    service: clean(payload.service, 80),
    timeline: clean(payload.timeline, 60),
    message: clean(payload.message, 2000),
    website: clean(payload.website, 200),
  };

  const errors = [];
  if (inquiry.website) errors.push("Spam check failed.");
  if (!["Consultation", "Quote", "Project question"].includes(inquiry.requestType)) errors.push("Choose a request type.");
  if (inquiry.name.length < 2) errors.push("Enter your name.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(inquiry.email)) errors.push("Enter a valid email address.");
  if (!allowedServices.has(inquiry.service)) errors.push("Choose a valid service.");
  if (inquiry.timeline && !allowedTimelines.has(inquiry.timeline)) errors.push("Choose a valid timeline.");
  if (inquiry.message.length < 20) errors.push("Tell us a little more about the project.");
  if ((inquiry.message.match(/https?:\/\//gi) || []).length > 3) errors.push("Too many links in the message.");

  return { inquiry, errors };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function textLine(label, value) {
  return `${label}: ${value || "Not provided"}`;
}

function buildInquiryEmail(inquiry, record) {
  const subject = `New AeroVista ${inquiry.requestType}: ${inquiry.name}`;
  const fields = [
    ["Request type", inquiry.requestType],
    ["Name", inquiry.name],
    ["Email", inquiry.email],
    ["Company", inquiry.company],
    ["Service", inquiry.service],
    ["Timeline", inquiry.timeline],
    ["Submitted", record.createdAt],
    ["Inquiry ID", record.id],
  ];

  const text = [
    "New inquiry from aerovistaanalytics.com",
    "",
    ...fields.map(([label, value]) => textLine(label, value)),
    "",
    "Message:",
    inquiry.message,
  ].join("\n");

  const rows = fields
    .map(
      ([label, value]) =>
        `<tr><th align="left" style="padding:6px 12px 6px 0;color:#071936;">${escapeHtml(label)}</th><td style="padding:6px 0;color:#1c2b43;">${escapeHtml(value || "Not provided")}</td></tr>`
    )
    .join("");

  const html = `
    <div style="font-family:Arial,sans-serif;color:#071936;line-height:1.5;">
      <h1 style="font-size:20px;margin:0 0 16px;">New AeroVista Analytics Inquiry</h1>
      <table style="border-collapse:collapse;margin-bottom:18px;">${rows}</table>
      <h2 style="font-size:16px;margin:0 0 8px;">Message</h2>
      <p style="white-space:pre-wrap;margin:0;color:#1c2b43;">${escapeHtml(inquiry.message)}</p>
    </div>
  `;

  return { subject, text, html };
}

async function sendInquiryEmail(inquiry, record) {
  if (!RESEND_API_KEY) {
    const error = new Error("Email service is not configured.");
    error.status = 503;
    throw error;
  }

  const email = buildInquiryEmail(inquiry, record);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
      "User-Agent": "aerovista-analytics-website/1.0",
      "Idempotency-Key": record.id,
    },
    body: JSON.stringify({
      from: CONTACT_FROM_EMAIL,
      to: [CONTACT_TO_EMAIL],
      reply_to: inquiry.email,
      subject: email.subject,
      text: email.text,
      html: email.html,
      tags: [
        { name: "source", value: "website" },
        { name: "request_type", value: inquiry.requestType.toLowerCase().replace(/\s+/g, "_") },
      ],
    }),
  });

  let result = {};
  try {
    result = await response.json();
  } catch {
    result = {};
  }

  if (!response.ok || !result.id) {
    const error = new Error("Email delivery failed.");
    error.status = response.status >= 500 ? 502 : 500;
    error.providerStatus = response.status;
    error.providerMessage = result.name || result.message || "unknown";
    throw error;
  }

  return result.id;
}

function logDeliveryError(error, record) {
  console.error(
    JSON.stringify({
      level: "error",
      event: "inquiry_email_delivery_failed",
      inquiryId: record.id,
      provider: "resend",
      providerStatus: error.providerStatus || null,
      providerMessage: error.providerMessage || error.message || "unknown",
      createdAt: new Date().toISOString(),
    })
  );
}

async function handleInquiry(req, res) {
  if (!isAllowedOrigin(req.headers.origin)) {
    sendJson(res, 403, { ok: false, error: "Request origin is not allowed." });
    return;
  }

  if (req.headers["sec-fetch-site"] === "cross-site") {
    sendJson(res, 403, { ok: false, error: "Cross-site requests are not allowed." });
    return;
  }

  if (!rateLimit(req)) {
    sendJson(res, 429, { ok: false, error: "Too many requests. Please try again later." });
    return;
  }

  const cookies = parseCookies(req.headers.cookie);
  const headerToken = req.headers["x-csrf-token"];
  if (!cookies.av_csrf || cookies.av_csrf !== headerToken || !isValidCsrfToken(headerToken)) {
    sendJson(res, 403, { ok: false, error: "Security token expired. Refresh the page and try again." });
    return;
  }

  if (!String(req.headers["content-type"] || "").startsWith("application/json")) {
    sendJson(res, 415, { ok: false, error: "Use application/json." });
    return;
  }

  try {
    const payload = await readJsonBody(req);
    const { inquiry, errors } = validateInquiry(payload);
    if (errors.length) {
      sendJson(res, 400, { ok: false, errors });
      return;
    }

    const record = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      site: PUBLIC_SITE_URL,
      publicContactEmail: PUBLIC_CONTACT_EMAIL,
      ipHash: crypto.createHash("sha256").update(getClientIp(req)).digest("hex"),
      inquiry,
    };

    let emailId;
    try {
      emailId = await sendInquiryEmail(inquiry, record);
    } catch (deliveryError) {
      logDeliveryError(deliveryError, record);
      sendJson(res, deliveryError.status || 502, {
        ok: false,
        error: "Your request could not be sent right now. Please email contact@aerovistaanalytics.com directly.",
      });
      return;
    }

    record.delivery = {
      provider: "resend",
      emailId,
      deliveredAt: new Date().toISOString(),
    };

    sendJson(res, 201, {
      ok: true,
      id: record.id,
      message: "Thanks. Your request was received, and AeroVista Analytics will follow up shortly.",
    });
  } catch (error) {
    sendJson(res, error.status || 500, { ok: false, error: error.message || "Unable to receive request." });
  }
}

function serveStatic(req, res, pathname) {
  let requestedPath;
  try {
    requestedPath = decodeURIComponent(pathname);
  } catch {
    sendText(res, 400, "Bad request");
    return;
  }

  if (requestedPath.includes("\0")) {
    sendText(res, 400, "Bad request");
    return;
  }

  if (requestedPath === "/") requestedPath = "/index.html";

  const normalized = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(ROOT, normalized);
  const relative = path.relative(ROOT, filePath);
  const firstSegment = relative.split(path.sep)[0];

  if (
    relative.startsWith("..") ||
    path.isAbsolute(relative) ||
    ["server.js", "package.json", ".env", ".env.example", "storage", "work"].includes(firstSegment)
  ) {
    sendText(res, 404, "Not found");
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      sendText(res, 404, "Not found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const headers = securityHeaders(mimeTypes[ext] || "application/octet-stream");
    if ([".css", ".js"].includes(ext)) {
      headers["Cache-Control"] = "public, max-age=3600";
    } else if ([".png", ".jpg", ".jpeg", ".svg", ".ico", ".webmanifest"].includes(ext)) {
      headers["Cache-Control"] = "public, max-age=86400";
    } else if ([".html", ".xml", ".txt"].includes(ext)) {
      headers["Cache-Control"] = "public, max-age=300";
    } else {
      headers["Cache-Control"] = "no-store";
    }
    res.writeHead(200, headers);
    res.end(req.method === "HEAD" ? undefined : data);
  });
}

const server = http.createServer((req, res) => {
  if (!isAllowedHost(req)) {
    sendText(res, 400, "Bad request");
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, { ok: true, service: "aerovista-analytics-website" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/csrf") {
    const token = createCsrfToken();
    res.writeHead(200, {
      ...securityHeaders("application/json; charset=utf-8"),
      "Set-Cookie": `av_csrf=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=7200${csrfCookieSecure}`,
    });
    res.end(JSON.stringify({ ok: true, csrfToken: token }));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/inquiries") {
    handleInquiry(req, res);
    return;
  }

  if (req.method === "GET" || req.method === "HEAD") {
    serveStatic(req, res, url.pathname);
    return;
  }

  sendText(res, 405, "Method not allowed");
});

server.requestTimeout = 15000;
server.headersTimeout = 16000;
server.keepAliveTimeout = 5000;
server.maxHeadersCount = 64;

server.on("clientError", (_error, socket) => {
  if (socket.writable) {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  }
});

server.listen(PORT, () => {
  console.log(`AeroVista Analytics website running at http://localhost:${PORT}`);
});
