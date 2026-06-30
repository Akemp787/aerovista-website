"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "https://aerovistaanalytics.com";
const PUBLIC_CONTACT_EMAIL = process.env.PUBLIC_CONTACT_EMAIL || "contact@aerovistaanalytics.com";
const ROOT = __dirname;
const STORAGE_DIR = path.join(ROOT, "storage");
const INQUIRY_FILE = path.join(STORAGE_DIR, "inquiries.jsonl");
const MAX_BODY_BYTES = 24 * 1024;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT = 6;
const csrfSecret = process.env.CSRF_SECRET || crypto.randomBytes(32).toString("hex");
const requestCounts = new Map();

const allowedServices = new Set([
  "Data Analysis & Reporting",
  "Business Intelligence & Dashboards",
  "Process & Performance Analysis",
  "Data Cleaning & Validation",
  "Custom Reports & Automation",
  "Analytics Strategy & Advisory",
  "Not sure yet",
]);

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
};

fs.mkdirSync(STORAGE_DIR, { recursive: true });

function securityHeaders(contentType = "text/plain; charset=utf-8") {
  return {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self'",
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

function sendJson(res, status, payload) {
  res.writeHead(status, securityHeaders("application/json; charset=utf-8"));
  res.end(JSON.stringify(payload));
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
    budget: clean(payload.budget, 60),
    message: clean(payload.message, 2000),
    website: clean(payload.website, 200),
  };

  const errors = [];
  if (inquiry.website) errors.push("Spam check failed.");
  if (!["Consultation", "Quote", "Project question"].includes(inquiry.requestType)) errors.push("Choose a request type.");
  if (inquiry.name.length < 2) errors.push("Enter your name.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(inquiry.email)) errors.push("Enter a valid email address.");
  if (!allowedServices.has(inquiry.service)) errors.push("Choose a valid service.");
  if (inquiry.message.length < 20) errors.push("Tell us a little more about the project.");

  return { inquiry, errors };
}

async function handleInquiry(req, res) {
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

    fs.appendFileSync(INQUIRY_FILE, `${JSON.stringify(record)}\n`, { mode: 0o600 });
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
  let requestedPath = decodeURIComponent(pathname);
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
    res.writeHead(404, securityHeaders());
    res.end("Not found");
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, securityHeaders());
      res.end("Not found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, securityHeaders(mimeTypes[ext] || "application/octet-stream"));
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, { ok: true, service: "aerovista-analytics-website" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/csrf") {
    const token = createCsrfToken();
    res.writeHead(200, {
      ...securityHeaders("application/json; charset=utf-8"),
      "Set-Cookie": `av_csrf=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=7200`,
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

  res.writeHead(405, securityHeaders());
  res.end("Method not allowed");
});

server.listen(PORT, () => {
  console.log(`AeroVista Analytics website running at http://localhost:${PORT}`);
});
