# AeroVista Analytics Website

Professional consulting website with a small Node.js backend for secure inquiry handling.

## Run Locally

```powershell
node server.js
```

Then open:

```text
http://localhost:3000
```

## Backend Features

- Serves the website pages and assets.
- Accepts consultation and quote requests at `POST /api/inquiries`.
- Uses CSRF protection through `GET /api/csrf`.
- Applies security headers, including CSP and frame protection.
- Uses a honeypot field and IP-based rate limiting.
- Validates and sanitizes submitted fields server-side.
- Stores inquiries privately in `storage/inquiries.jsonl`.

The `storage` folder is blocked from public web access by `server.js`.

## Environment Variables

Copy `.env.example` values into your hosting provider's environment settings:

```text
PORT=3000
PUBLIC_SITE_URL=https://aerovistaanalytics.com
PUBLIC_CONTACT_EMAIL=contact@aerovistaanalytics.com
OWNER_EMAIL=kempa@aerovistaanalytics.com
```

Use `contact@aerovistaanalytics.com` publicly and forward it to the owner inbox through your domain email provider.

## Deploy With Render

Deploy this as a Node.js app, not as a static-only site, because the contact form depends on the backend API.

Recommended Render setup:

```text
Build command: npm install
Start command: npm start
```

The included `render.yaml` can also be used as a Render Blueprint.

## Editing Later

1. Edit the HTML pages, `styles.css`, `script.js`, or `server.js`.
2. Test locally with `node server.js`.
3. Commit the change.
4. Push to GitHub.
5. Render redeploys from the GitHub repo.

Good hosting options include Render, Railway, Fly.io, DigitalOcean App Platform, or any VPS that can run Node.js.
