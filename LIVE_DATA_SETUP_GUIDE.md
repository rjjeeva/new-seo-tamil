# Live SEO Dashboard — Region Security Guarding

Target site:
https://regionsecurityguarding.co.uk/

## Goal

The dashboard must use one fixed site only and must never display demo/fake values.

Data flow:

Website / APIs -> backend collector -> master JSON -> dashboard

## Required live sources

1. Google Search Console API
   - clicks
   - impressions
   - CTR
   - average position
   - queries/keywords
   - pages
   - countries
   - search appearance

2. Google PageSpeed Insights API
   - performance
   - accessibility
   - best practices
   - SEO
   - Core Web Vitals

3. Live website crawler
   - HTTP status
   - HTTPS
   - title
   - meta description
   - H1
   - canonical
   - robots.txt
   - sitemap.xml
   - images and missing alt
   - internal/external links

4. Google Analytics Data API (optional but required for live GA4 metrics)
   - users
   - sessions
   - page views
   - engagement/bounce metrics

5. Backlink provider (required for real backlink numbers)
   - referring domains
   - backlinks
   - dofollow/nofollow
   The website itself cannot provide a complete external backlink index.

6. AI visibility provider
   - Only use real provider data. Do not infer AI visibility from normal HTML or pretend GSC search appearance is ChatGPT/Gemini visibility.

## Master JSON

Use one JSON document as the dashboard contract, for example:

data/regionsecurityguarding.json

Every value must contain real data or an explicit unavailable status. Never use demo numbers.

Example unavailable value:

{
  "status": "unavailable",
  "reason": "Google Analytics is not connected"
}

## Fixed site

Use:

SEO_SITE_URL=https://regionsecurityguarding.co.uk/

Remove/disable:
- site selector
- multiple-site discovery
- demo values
- mock fallback values

## Recommended endpoints

GET /api/seo-data
Returns the latest normalized JSON.

POST /api/refresh
Fetches live sources, updates the JSON, and returns the latest result.

## Dashboard

The frontend should call:

fetch('/api/seo-data', { cache: 'no-store' })

and render only the returned JSON.

## Environment variables

Keep secrets server-side. Do not commit real secrets.

Recommended variables:

SEO_SITE_URL=https://regionsecurityguarding.co.uk/
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
PAGESPEED_API_KEY=
GA4_PROPERTY_ID=
BACKLINK_API_KEY=
BACKLINK_PROVIDER=
AI_VISIBILITY_API_KEY=

## Important

Do not put API keys or OAuth refresh tokens in public/index.html or browser JavaScript.

## Deployment

1. Add environment variables to the deployment platform.
2. Make sure the Google OAuth redirect URI exactly matches the deployed callback URL.
3. Verify the Search Console property is verified for the Google account.
4. Connect GA4 only if GA4 metrics are required.
5. Connect a backlink provider if backlink metrics are required.
6. Deploy.
7. Open /api/seo-data and verify that it returns real values/statuses.
8. Open the dashboard and confirm it contains no demo values.
