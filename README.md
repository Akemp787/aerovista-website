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
- Creates Stripe Checkout Sessions for the Member Data Readiness Kit at `POST /api/member-kit/checkout`.
- Verifies Stripe webhooks at `POST /api/stripe/webhook`.
- Emails the Member Data Readiness Kit after Stripe confirms successful payment.
- Uses CSRF protection through `GET /api/csrf`.
- Applies security headers, including CSP and frame protection.
- Uses a honeypot field and IP-based rate limiting.
- Validates and sanitizes submitted fields server-side.
- Sets the visitor email as the email `Reply-To`.
- Does not store inquiry bodies on the web server; delivered email is the inquiry record.
- Stores only minimal product fulfillment status server-side to prevent duplicate delivery.
- Restricts accepted hostnames and blocks cross-site form posts.
- Uses short request timeouts and rejects malformed URLs safely.
- Logs email delivery errors server-side without returning provider details to visitors.

There is no login system or customer account area. Payment is handled through Stripe-hosted Checkout; card details never touch this server.

## Environment Variables

Copy `.env.example` values into your hosting provider's environment settings:

```text
PORT=3000
PUBLIC_SITE_URL=https://aerovistaanalytics.com
ALLOWED_HOSTS=aerovistaanalytics.com,www.aerovistaanalytics.com,aerovista-analytics.onrender.com
PUBLIC_CONTACT_EMAIL=contact@aerovistaanalytics.com
CONTACT_TO_EMAIL=contact@aerovistaanalytics.com
CONTACT_FROM_EMAIL=AeroVista Analytics <contact@aerovistaanalytics.com>
RESEND_API_KEY=your_resend_api_key
CSRF_SECRET=generate_a_long_random_secret
STRIPE_SECRET_KEY=sk_live_or_test_key
STRIPE_WEBHOOK_SECRET=whsec_webhook_signing_secret
MEMBER_KIT_STRIPE_PRICE_ID=price_optional_precreated_price_id
MEMBER_KIT_PRICE_CENTS=1700
MEMBER_KIT_DELIVERY_DIR=
```

Use `contact@aerovistaanalytics.com` publicly and forward it to the owner inbox through your domain email provider.

Do not commit real secret values. Add `RESEND_API_KEY`, `CSRF_SECRET`, `STRIPE_SECRET_KEY`, and `STRIPE_WEBHOOK_SECRET` only in Render's Environment settings.

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
ALLOWED_HOSTS=aerovistaanalytics.com,www.aerovistaanalytics.com,aerovista-analytics.onrender.com
CSRF_SECRET=<long random string>
STRIPE_SECRET_KEY=<your Stripe secret key>
STRIPE_WEBHOOK_SECRET=<your Stripe webhook signing secret>
MEMBER_KIT_STRIPE_PRICE_ID=<optional Stripe Price ID>
MEMBER_KIT_PRICE_CENTS=1700
```

6. Redeploy the Render service.
7. Submit a test inquiry on the live contact form. The page should show success only after Resend confirms the email was accepted.

If Resend rejects the message or the API key is missing, the visitor sees a generic error asking them to email `contact@aerovistaanalytics.com` directly, while the server logs a sanitized delivery error.

### Stripe Product Delivery Setup

The Member Data Readiness Kit checkout uses Stripe-hosted Checkout. The frontend never receives the Stripe secret key, and card details are handled by Stripe.

1. In Stripe, create or confirm your account branding under **Settings > Branding**.
2. Optional but recommended: create a product named `Member Data Readiness Kit` with a one-time price of `$17.00 USD`.
3. Copy the Stripe Price ID, which starts with `price_`, into Render as `MEMBER_KIT_STRIPE_PRICE_ID`.
4. If `MEMBER_KIT_STRIPE_PRICE_ID` is blank, the backend creates Checkout Sessions with server-side `price_data` using `MEMBER_KIT_PRICE_CENTS=1700`.
5. In Stripe, create a webhook endpoint:

```text
https://aerovistaanalytics.com/api/stripe/webhook
```

6. Subscribe the webhook endpoint to these events:

```text
checkout.session.completed
checkout.session.async_payment_succeeded
checkout.session.async_payment_failed
```

7. Copy the webhook signing secret, which starts with `whsec_`, into Render as `STRIPE_WEBHOOK_SECRET`.
8. Add `STRIPE_SECRET_KEY` in Render. Use test keys while testing and live keys only when ready to accept real payments.
9. Add the paid product files before accepting live purchases:

```text
private/downloads/member-data-readiness-kit/Member_Data_Readiness_Kit.zip
```

The backend emails the ZIP after verified payment. If the ZIP is not present, it looks for:

```text
private/downloads/member-data-readiness-kit/Member_Data_Readiness_Kit_Guide.pdf
private/downloads/member-data-readiness-kit/Member_Data_Readiness_Kit_Workbook.xlsx
```

The `private/` folder is blocked from direct browser access by `server.js`; do not place paid files in `assets/` or any public route.

10. Redeploy Render after adding environment variables or delivery files.
11. Test with Stripe test mode and the test card `4242 4242 4242 4242`.

Stripe fulfillment is webhook-based. The thank-you page tells buyers to check email, but the email is only sent after Stripe confirms payment through a signed webhook.

### SEO and Launch Files

The site includes `robots.txt`, `sitemap.xml`, `site.webmanifest`, social sharing metadata, and a favicon. If a page is renamed or removed, update `sitemap.xml` and the page's canonical URL at the same time.

## Editing Later

1. Edit the HTML pages, `styles.css`, `script.js`, or `server.js`.
2. Test locally with `node server.js`.
3. Commit the change.
4. Push to GitHub.
5. Render redeploys from the GitHub repo.

Good hosting options include Render, Railway, Fly.io, DigitalOcean App Platform, or any VPS that can run Node.js.
