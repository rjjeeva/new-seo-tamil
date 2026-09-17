# SEO Pulse OAuth Dashboard

Local-first Google OAuth + Search Console dashboard.

## Run

1. Copy `.env.example` to `.env`.
2. Put the real Google OAuth Client ID, Client Secret and PageSpeed key in `.env`.
3. Make sure Google Cloud OAuth redirect URI is exactly:
   `http://localhost:3000/oauth2callback`
4. Run `npm run dev`.
5. Open `http://localhost:3000`.
6. Click **Sign in with Google**.
7. Authorize Search Console access.
8. Choose a property from the automatic dropdown.

No service-account JSON is used by this version.
