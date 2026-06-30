# AeroVista Analytics Website

Professional consulting website with a small Node.js backend for secure inquiry handling.

## Run Locally

```powershell
$env:PUBLIC_SITE_URL="http://localhost:3000"
node server.js
```

Then open:

```text
http://localhost:3000
```

Set `PUBLIC_SITE_URL` to the local HTTP URL while testing locally. In production it should remain `https://aerovistaanalytics.com` so the CSRF cookie is marked `Secure`.

## Backend Features

- Serves the website pages and assets.
- Accepts consultation and quote requests at `POST /api/inquiries`.
- Sends each valid inquiry to `contact@aerovistaanalytics.com` through Resend.
- Uses CSRF protection through `GET /api/csrf`.
- Applies security headers, including CSP and frame protection.
- Uses a honeypot field and IP-based rate limiting.
- Validates and sanitizes submitted fields server-side.
- Sets the visitor email as the email `Reply-To`.
- Stores successfully delivered inquiries privately in `storage/inquiries.jsonl`.
- Logs email delivery errors server-side without returning provider details to visitors.

The `storage` folder is blocked from public web access by `server.js`. On Render's free web service filesystem, this file should be treated as a temporary operational log rather than permanent storage; the delivered email is the primary inquiry record unless durable storage is added later.

## Environment Variables

Copy `.env.example` values into your hosting provider's environment settings:

```text
PORT=3000
PUBLIC_SITE_URL=https://aerovistaanalytics.com
PUBLIC_CONTACT_EMAIL=contact@aerovistaanalytics.com
CONTACT_TO_EMAIL=contact@aerovistaanalytics.com
CONTACT_FROM_EMAIL=AeroVista Analytics <contact@aerovistaanalytics.com>
OWNER_EMAIL=kempa@aerovistaanalytics.com
RESEND_API_KEY=your_resend_api_key
CSRF_SECRET=generate_a_long_random_secret
```

Use `contact@aerovistaanalytics.com` publicly and forward it to the owner inbox through your domain email provider.

Do not commit real secret values. Add `RESEND_API_KEY` and `CSRF_SECRET` only in Render's Environment settings.

## Deploy With Render

Deploy this as a Node.js app, not as a static-only site, because the contact form depends on the backend API.

Recommended Render setup:

```text
Build command: npm install
Start command: npm start
```

The included `render.yaml` can also be used as a Render Blueprint.

### Email Delivery Setup

This backend uses Resend's server-side email API. The frontend never receives the API key.

1. Create a Resend account and verify `aerovistaanalytics.com` as a sending domain.
2. Add the DNS records Resend gives you at your domain registrar.
3. In Resend, create an API key with permission to send email.
4. In Render, open the AeroVista service, then go to **Environment**.
5. Add these environment variables:

```text
RESEND_API_KEY=<your Resend API key>
CONTACT_TO_EMAIL=contact@aerovistaanalytics.com
CONTACT_FROM_EMAIL=AeroVista Analytics <contact@aerovistaanalytics.com>
PUBLIC_CONTACT_EMAIL=contact@aerovistaanalytics.com
PUBLIC_SITE_URL=https://aerovistaanalytics.com
CSRF_SECRET=<long random string>
```

6. Redeploy the Render service.
7. Submit a test inquiry on the live contact form. The page should show success only after Resend confirms the email was accepted.

If Resend rejects the message or the API key is missing, the visitor sees a generic error asking them to email `contact@aerovistaanalytics.com` directly, while the server logs a sanitized delivery error.

### SEO and Launch Files

The site includes `robots.txt`, `sitemap.xml`, `site.webmanifest`, social sharing metadata, and a favicon. If a page is renamed or removed, update `sitemap.xml` and the page's canonical URL at the same time.

## Editing Later

1. Edit the HTML pages, `styles.css`, `script.js`, or `server.js`.
2. Test locally with `node server.js`.
3. Commit the change.
4. Push to GitHub.
5. Render redeploys from the GitHub repo.

Good hosting options include Render, Railway, Fly.io, DigitalOcean App Platform, or any VPS that can run Node.js.
