# XSS Hunter for Cloudflare Workers

XSS Hunter rewritten from the ground up to run entirely on **Cloudflare Workers**.

This allows you to host your own highly scalable, serverless XSS Hunter instance with **zero maintenance and effectively zero cost** (fits comfortably in Cloudflare's free tier).

> **Note:** Email notifications require the **Workers Paid** plan. The free plan supports all other features (D1, R2, the web panel).

## What is this?
The original [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express) was a Node.js monolithic application utilizing Express, PostgreSQL, Sequelize, and various other dependencies. This fork completely refactors the application to be serverless:
- **Cloudflare Workers** (Compute) replaces Node.js / Express
- **Cloudflare D1** (Serverless SQLite) replaces PostgreSQL / Sequelize
- **Cloudflare R2** (Object Storage) replaces Local Filesystem / GCS
- **Cloudflare Email Routing** replaces external SMTP / SendGrid for email alerts
- Dependencies like `bcrypt` and `multer` have been replaced with native Web Crypto API and standard `FormData` parsing.

## Features
- **Managed XSS payload fires**: Manage all of your XSS payloads in your XSS Hunter account's control panel.
- **Serverless & Edge-native**: Extremely fast performance globally, entirely hosted on Cloudflare's edge network.
- **No maintenance**: Forget about managing Docker containers, Linux servers, database backups, or memory limits.
- **Full Page Screenshots**: Captures the vulnerable page just like the original XSS Hunter.
- **Correlated Injections**: Understand what exact injection attempt triggered a payload.
- **Email Notifications**: Native integration with Cloudflare Email Routing to receive payload fires in your inbox. *(Requires Workers Paid plan — the `send_email` binding is not available on the free tier.)*
- **Google OAuth Login**: Easy and secure authentication using your Google Workspace / Gmail account.

## Environment Variables
The following environment variables are required and must be set via `wrangler.toml` or using Cloudflare Workers Secrets (`wrangler secret put <KEY>`):

| Variable | Description | Where to set |
|----------|-------------|--------------|
| `XSS_HOSTNAME` | The domain name where the worker is hosted (e.g., `xss.yourdomain.com`). | `wrangler.toml` (`[vars]`) |
| `SSL_CONTACT_EMAIL` | Admin email address for the instance. | `wrangler.toml` (`[vars]`) |
| `BLUR_SCREENSHOTS` | Set to `"true"` to blur screenshots in the UI. | `wrangler.toml` (`[vars]`) |
| `EMAIL_FROM` | The email address from which payload alerts will be sent. | Secret |
| `EMAIL_NOTIFICATIONS_ENABLED` | Set to `"true"` to enable email alerts. | Secret |
| `JWT_SECRET` | A secure, random string used to sign session cookies. | Secret |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID for login. | Secret |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret for login. | Secret |

For installation and deployment instructions, see [INSTALL.md](INSTALL.md).
