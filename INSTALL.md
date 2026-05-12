# Installation Guide

Follow these steps to deploy XSS Hunter on Cloudflare Workers.

## Prerequisites

1. A [Cloudflare](https://dash.cloudflare.com/sign-up) account.
2. A domain name registered or managed via Cloudflare.
3. [Node.js](https://nodejs.org/) installed locally.
4. Wrangler CLI installed (`npm install -g wrangler`).

## Step 1: Cloudflare R2 Setup (Screenshots)

XSS Hunter uses Cloudflare R2 to store screenshots of payload fires.

1. Go to the Cloudflare Dashboard -> **R2 Object Storage**.
2. **Note**: You must have a billing method on file to enable R2. However, the free tier includes 10GB of storage per month, which is more than enough for typical usage.
3. Enable R2 if you haven't already.
4. Run the following command in your terminal to create a bucket named `xsshunter-screenshots`:
   ```bash
   wrangler r2 bucket create xsshunter-screenshots
   ```

## Step 2: Cloudflare D1 Setup (Database)

XSS Hunter uses Cloudflare D1 for its database.

1. Create a new D1 database:
   ```bash
   wrangler d1 create xsshunter-d1
   ```
2. The command will output a `database_id`. Open `workers/wrangler.toml` and replace the `database_id` value under `[[d1_databases]]` with the one you just created.

## Step 3: Google Workspace Setup (OAuth)

To securely log into your XSS Hunter panel, you must set up Google OAuth.

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new Project (or select an existing one).
3. Navigate to **APIs & Services** -> **OAuth consent screen**.
   - Choose **External** (or Internal if you use Google Workspace and want to restrict it to your org).
   - Fill in the required fields (App name, Support email, Developer contact).
4. Navigate to **Credentials** -> **Create Credentials** -> **OAuth client ID**.
   - **Application type**: Web application.
   - **Name**: XSS Hunter
   - **Authorized redirect URIs**: `https://<YOUR_XSS_HOSTNAME>/oauth-login` (e.g., `https://xss.yourdomain.com/oauth-login`).
5. Click **Create**. You will be given a **Client ID** and **Client Secret**. Keep these safe.

## Step 4: Configure Environment Variables

Navigate to the `workers/` directory and configure the variables.

1. Edit `workers/wrangler.toml`:
   - Set `XSS_HOSTNAME` to the domain/subdomain you plan to use (e.g., `xss.yourdomain.com`).
   - Ensure the `database_id` matches your D1 database.
   - Ensure the `pattern` under `[[routes]]` matches your domain.

2. Set the secure secrets. Run the following commands and paste the values when prompted:
   ```bash
   wrangler secret put GOOGLE_CLIENT_ID
   wrangler secret put GOOGLE_CLIENT_SECRET
   wrangler secret put JWT_SECRET
   ```
   *(For `JWT_SECRET`, generate a long random string).*

## Step 5: (Optional) Cloudflare Email Routing Setup

If you want to receive email notifications when a payload fires, configure Cloudflare Email Routing.

1. Go to the Cloudflare Dashboard -> Your Domain -> **Email** -> **Email Routing**.
2. Enable Email Routing.
3. In **Settings**, configure the routing rules or simply ensure the domain is configured to allow Workers to send emails.
4. Enable email notifications in XSS Hunter by setting the following secrets:
   ```bash
   wrangler secret put EMAIL_FROM
   wrangler secret put EMAIL_NOTIFICATIONS_ENABLED
   ```
   - Set `EMAIL_FROM` to an address on your domain (e.g., `alerts@xss.yourdomain.com`).
   - Set `EMAIL_NOTIFICATIONS_ENABLED` to `true`.

## Step 6: Deploy Database Migrations

Apply the database schema to your D1 database:

```bash
cd workers
npm run db:remote
```

## Step 7: Deploy the Worker

Deploy the backend worker to Cloudflare:

```bash
npm run deploy
```

## Step 8: Build and Deploy the Frontend

XSS Hunter's frontend is a Single Page Application (SPA). The worker serves this application under the `/app/` route. First, build the frontend and upload it to the `xsshunter-screenshots` R2 bucket (under the `frontend/` prefix).

```bash
cd ../front-end
npm install
npm run build
```
Upload the `dist` directory to your R2 bucket. *Note: You can use `wrangler r2 object put` or the Cloudflare Dashboard to upload these files.*

Once everything is deployed, visit `https://<YOUR_XSS_HOSTNAME>/login` to authenticate!
