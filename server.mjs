import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  getOverview,
  pageSpeed,
  crawlSite,
  getSites,
  googleLoginUrl,
  handleGoogleCallback,
  getAuthenticatedUser,
  clearAuthCookie,
  getGoogleSites,
  getOverviewForOAuth,
  getBingOverview,
  collectLiveSeoData,
  saveLiveSeoJson
} from './lib.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));


// ======================================================
// ENV LOADER
// ======================================================

function loadEnv() {
  const f = path.join(__dirname, '.env');

  if (!fs.existsSync(f)) return;

  for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);

    if (!m || process.env[m[1]]) continue;

    let v = m[2].trim();

    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }

    process.env[m[1]] = v;
  }
}

loadEnv();


// ======================================================
// SERVER CONFIG
// ======================================================

const port = Number(process.env.PORT || 3000);

const mime = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon'
};


// ======================================================
// RESPONSE HELPER
// ======================================================

function send(
  res,
  status,
  body,
  type = 'text/plain',
  extra = {}
) {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    ...extra
  });

  res.end(body);
}


// ======================================================
// COOKIE HELPER
// ======================================================

function cookieValue(req, name) {
  const cookies = String(
    req.headers.cookie || ''
  ).split(';');

  for (const c of cookies) {
    const [k, ...rest] = c.trim().split('=');

    if (k === name) {
      return decodeURIComponent(
        rest.join('=')
      );
    }
  }

  return '';
}


// ======================================================
// COOKIE SET / CLEAR
// ======================================================

function setCookie(
  name,
  value,
  maxAge = 31536000
) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAge}`
  ].join('; ');
}


function clearCookie(name) {
  return [
    `${name}=`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Path=/',
    'Max-Age=0'
  ].join('; ');
}


// ======================================================
// BING TOKEN ENCRYPTION
// ======================================================

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error(
      'SESSION_SECRET is missing'
    );
  }

  return crypto
    .createHash('sha256')
    .update(secret)
    .digest();
}


function encryptBingToken(refreshToken) {
  const key = getSessionSecret();

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(
      refreshToken,
      'utf8'
    ),
    cipher.final()
  ]);

  const authTag =
    cipher.getAuthTag();

  return [
    iv.toString('base64url'),
    authTag.toString('base64url'),
    encrypted.toString('base64url')
  ].join('.');
}


function decryptBingToken(value) {
  try {
    if (!value) {
      return '';
    }

    const parts = value.split('.');

    if (parts.length !== 3) {
      return '';
    }

    const [
      ivPart,
      tagPart,
      dataPart
    ] = parts;

    const key =
      getSessionSecret();

    const iv =
      Buffer.from(
        ivPart,
        'base64url'
      );

    const authTag =
      Buffer.from(
        tagPart,
        'base64url'
      );

    const encrypted =
      Buffer.from(
        dataPart,
        'base64url'
      );

    const decipher =
      crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        iv
      );

    decipher.setAuthTag(authTag);

    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString('utf8');

  } catch (e) {

    console.error(
      'Bing token decrypt failed:',
      e.message
    );

    return '';
  }
}


// ======================================================
// SERVER
// ======================================================

const server = http.createServer(
  async (req, res) => {

    try {

      const protocol =
        req.headers['x-forwarded-proto'] ||
        'http';

      const u = new URL(
        req.url,
        `${protocol}://${req.headers.host}`
      );


      // ==================================================
      // BING WEBMASTER OAUTH LOGIN
      // ==================================================

      if (
        u.pathname ===
        '/bing/oauth/login'
      ) {

        const clientId =
          process.env.BING_CLIENT_ID;

        const redirectUri =
          process.env.BING_REDIRECT_URI ||
          'https://seotamil.vercel.app/bing/oauth/callback';


        if (!clientId || !redirectUri) {

          return send(
            res,
            500,
            JSON.stringify({
              error:
                'Bing OAuth configuration is missing.'
            }),
            'application/json'
          );
        }


        // ----------------------------------------------
        // CSRF STATE
        // ----------------------------------------------

        const state =
          crypto.randomBytes(32)
            .toString('hex');


        const params =
          new URLSearchParams({
            response_type: 'code',
            client_id: clientId,
            redirect_uri: redirectUri,
            scope: 'Webmaster.read',
            state
          });


        const authorizeUrl =
          `https://www.bing.com/webmasters/OAuth/authorize?${params.toString()}`;


        return send(
          res,
          302,
          '',
          'text/plain',
          {
            location:
              authorizeUrl,

            'set-cookie':
              `bing_oauth_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
          }
        );
      }


      // ==================================================
      // BING WEBMASTER OAUTH CALLBACK
      // ==================================================

      if (
        u.pathname ===
        '/bing/oauth/callback'
      ) {

        const code =
          u.searchParams.get('code');

        const error =
          u.searchParams.get('error');

        const errorDescription =
          u.searchParams.get(
            'error_description'
          );

        const returnedState =
          u.searchParams.get('state');

        const savedState =
          cookieValue(
            req,
            'bing_oauth_state'
          );


        // ----------------------------------------------
        // BING ERROR
        // ----------------------------------------------

        if (error) {

          return send(
            res,
            400,
            JSON.stringify({
              error:
                'Bing authorization denied',

              details:
                errorDescription ||
                error
            }),
            'application/json'
          );
        }


        // ----------------------------------------------
        // STATE VALIDATION
        // ----------------------------------------------

        if (
          !returnedState ||
          !savedState ||
          returnedState !== savedState
        ) {

          return send(
            res,
            400,
            JSON.stringify({
              error:
                'Invalid Bing OAuth state'
            }),
            'application/json'
          );
        }


        // ----------------------------------------------
        // CODE VALIDATION
        // ----------------------------------------------

        if (!code) {

          return send(
            res,
            400,
            JSON.stringify({
              error:
                'Bing authorization code missing'
            }),
            'application/json'
          );
        }


        try {

          const clientId =
            process.env.BING_CLIENT_ID;

          const clientSecret =
            process.env.BING_CLIENT_SECRET;

          const redirectUri =
            process.env.BING_REDIRECT_URI ||
            'https://seotamil.vercel.app/bing/oauth/callback';


          if (
            !clientId ||
            !clientSecret
          ) {

            throw new Error(
              'BING_CLIENT_ID or BING_CLIENT_SECRET is missing.'
            );
          }


          // --------------------------------------------
          // EXCHANGE CODE FOR TOKEN
          // --------------------------------------------

          const tokenResponse =
            await fetch(
              'https://www.bing.com/webmasters/oauth/token',
              {
                method: 'POST',

                headers: {
                  'content-type':
                    'application/x-www-form-urlencoded'
                },

                body:
                  new URLSearchParams({
                    client_id:
                      clientId,

                    client_secret:
                      clientSecret,

                    code,

                    redirect_uri:
                      redirectUri,

                    grant_type:
                      'authorization_code'
                  }).toString()
              }
            );


          const tokenData =
            await tokenResponse.json();


          // --------------------------------------------
          // TOKEN ERROR
          // --------------------------------------------

          if (!tokenResponse.ok) {

            console.error(
              'Bing OAuth token error:',
              tokenData
            );

            return send(
              res,
              400,
              JSON.stringify({
                error:
                  'Bing token exchange failed',

                details:
                  tokenData
              }),
              'application/json'
            );
          }


          // --------------------------------------------
          // REFRESH TOKEN CHECK
          // --------------------------------------------

          if (
            !tokenData.refresh_token
          ) {

            return send(
              res,
              400,
              JSON.stringify({
                error:
                  'Bing did not return a refresh token.'
              }),
              'application/json'
            );
          }


          // --------------------------------------------
          // ENCRYPT REFRESH TOKEN
          // --------------------------------------------

          const encryptedToken =
            encryptBingToken(
              tokenData.refresh_token
            );


          console.log(
            'Bing OAuth successful'
          );


          // --------------------------------------------
          // STORE ENCRYPTED TOKEN IN COOKIE
          // --------------------------------------------

          return send(
            res,
            302,
            '',
            'text/plain',
            {
              location:
                '/?bing_connected=1',

              'set-cookie': [
                setCookie(
                  'bing_auth',
                  encryptedToken
                ),

                clearCookie(
                  'bing_oauth_state'
                )
              ]
            }
          );

        } catch (e) {

          console.error(
            'Bing OAuth callback error:',
            e
          );


          return send(
            res,
            500,
            JSON.stringify({
              error:
                'Bing OAuth callback failed',

              details:
                e.message
            }),
            'application/json'
          );
        }
      }


      // ==================================================
      // BING LOGOUT
      // ==================================================

      if (
        u.pathname ===
        '/bing/oauth/logout'
      ) {

        return send(
          res,
          302,
          '',
          'text/plain',
          {
            location: '/',

            'set-cookie':
              clearCookie(
                'bing_auth'
              )
          }
        );
      }


      // ==================================================
      // GOOGLE LOGIN
      // ==================================================

      if (
        u.pathname ===
        '/auth/google'
      ) {

        const {
          url,
          stateCookie
        } = googleLoginUrl();


        return send(
          res,
          302,
          '',
          'text/plain',
          {
            location: url,

            'set-cookie':
              `oauth_state=${encodeURIComponent(stateCookie)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`
          }
        );
      }


      // ==================================================
      // GOOGLE CALLBACK
      // ==================================================

      if (
        u.pathname ===
        '/oauth2callback'
      ) {

        const stateCookie =
          cookieValue(
            req,
            'oauth_state'
          );


        const result =
          await handleGoogleCallback(
            u.searchParams.get('code'),
            u.searchParams.get('state'),
            stateCookie
          );


        return send(
          res,
          302,
          '',
          'text/plain',
          {
            location: '/',

            'set-cookie': [
              `seo_auth=${encodeURIComponent(result.authCookie)}; HttpOnly; Secure=${protocol === 'https'}; SameSite=Lax; Path=/; Max-Age=2592000`,

              'oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
            ]
          }
        );
      }


      // ==================================================
      // GOOGLE LOGOUT
      // ==================================================

      if (
        u.pathname ===
        '/auth/logout' &&
        req.method === 'POST'
      ) {

        return send(
          res,
          204,
          '',
          'text/plain',
          {
            'set-cookie':
              clearAuthCookie()
          }
        );
      }


      // ==================================================
      // SESSION
      // ==================================================

      if (
        u.pathname ===
        '/api/session'
      ) {

        const user =
          await getAuthenticatedUser(
            cookieValue(
              req,
              'seo_auth'
            )
          );


        const bingToken =
          decryptBingToken(
            cookieValue(
              req,
              'bing_auth'
            )
          );


        return send(
          res,
          200,
          JSON.stringify({
            authenticated:
              !!user,

            user:
              user || null,

            bingConnected:
              !!bingToken
          }),
          'application/json'
        );
      }


      // ==================================================
      // GOOGLE SITES
      // ==================================================

      if (
        u.pathname ===
        '/api/sites'
      ) {

        const user =
          await getAuthenticatedUser(
            cookieValue(
              req,
              'seo_auth'
            )
          );


        if (!user) {

          return send(
            res,
            401,
            JSON.stringify({
              error:
                'Google login required'
            }),
            'application/json'
          );
        }


        const sites =
          await getGoogleSites(
            user.refreshToken
          );


        return send(
          res,
          200,
          JSON.stringify({
            sites
          }),
          'application/json'
        );
      }


      // ==================================================
      // SEO DATA
      // ==================================================

      if (
        u.pathname ===
        '/api/seo-data'
      ) {

        const user =
          await getAuthenticatedUser(
            cookieValue(
              req,
              'seo_auth'
            )
          );


        const bingRefreshToken =
          decryptBingToken(
            cookieValue(
              req,
              'bing_auth'
            )
          );


        const data =
          await collectLiveSeoData({
            refreshToken:
              user?.refreshToken ||
              null,

            bingRefreshToken:
              bingRefreshToken ||
              null
          });


        await saveLiveSeoJson(
          data
        );


        return send(
          res,
          200,
          JSON.stringify(data),
          'application/json'
        );
      }


      // ==================================================
      // REFRESH SEO DATA
      // ==================================================

      if (
        u.pathname ===
        '/api/refresh' &&
        req.method === 'POST'
      ) {

        const user =
          await getAuthenticatedUser(
            cookieValue(
              req,
              'seo_auth'
            )
          );


        const bingRefreshToken =
          decryptBingToken(
            cookieValue(
              req,
              'bing_auth'
            )
          );


        const data =
          await collectLiveSeoData({
            refreshToken:
              user?.refreshToken ||
              null,

            bingRefreshToken:
              bingRefreshToken ||
              null
          });


        await saveLiveSeoJson(
          data
        );


        return send(
          res,
          200,
          JSON.stringify(data),
          'application/json'
        );
      }


      // ==================================================
      // GOOGLE OVERVIEW
      // ==================================================

      if (
        u.pathname ===
        '/api/overview'
      ) {

        const site =
          u.searchParams.get(
            'site'
          ) || undefined;


        const user =
          await getAuthenticatedUser(
            cookieValue(
              req,
              'seo_auth'
            )
          );


        if (user) {

          return send(
            res,
            200,
            JSON.stringify(
              await getOverviewForOAuth(
                site,
                user.refreshToken
              )
            ),
            'application/json'
          );
        }


        // Keep old demo/configured-site
        // route available if MOCK_MODE=true

        if (
          String(
            process.env.MOCK_MODE
          ).toLowerCase() === 'true'
        ) {

          return send(
            res,
            200,
            JSON.stringify(
              await getOverview(
                site
              )
            ),
            'application/json'
          );
        }


        return send(
          res,
          401,
          JSON.stringify({
            error:
              'Google login required'
          }),
          'application/json'
        );
      }


      // ==================================================
      // BING WEBMASTER API
      // ==================================================

      if (
        u.pathname ===
        '/api/bing'
      ) {

        const site =
          u.searchParams.get(
            'site'
          ) || undefined;


        const encryptedToken =
          cookieValue(
            req,
            'bing_auth'
          );


        const refreshToken =
          decryptBingToken(
            encryptedToken
          );


        try {

          const d =
            await getBingOverview(
              site,
              refreshToken ||
                null
            );


          return send(
            res,
            200,
            JSON.stringify(d),
            'application/json'
          );

        } catch (e) {

          console.error(
            'Bing API error:',
            e
          );


          return send(
            res,
            200,
            JSON.stringify({
              available: false,

              reason:
                e.message ||
                'Bing API unavailable'
            }),
            'application/json'
          );
        }
      }


      // ==================================================
      // PAGESPEED
      // ==================================================

      if (
        u.pathname ===
        '/api/pagespeed'
      ) {

        const selected =
          u.searchParams.get(
            'url'
          ) ||
          process.env.GSC_SITE_URL;


        const d =
          await pageSpeed(
            selected
          );


        return send(
          res,
          200,
          JSON.stringify(d),
          'application/json'
        );
      }


      // ==================================================
      // CRAWLER
      // ==================================================

      if (
        u.pathname ===
        '/api/crawl'
      ) {

        const selected =
          u.searchParams.get(
            'url'
          ) ||
          process.env.GSC_SITE_URL;


        const d =
          await crawlSite(
            selected
          );


        return send(
          res,
          200,
          JSON.stringify(d),
          'application/json'
        );
      }


      // ==================================================
      // STATIC FILES
      // ==================================================

      let p =
        u.pathname === '/'
          ? '/index.html'
          : u.pathname;


      p =
        path
          .normalize(p)
          .replace(
            /^([.][.][\\/])+/,
            ''
          );


      const publicRoot =
        path.join(
          __dirname,
          'public'
        );


      const file =
        path.join(
          publicRoot,
          p
        );


      // Prevent path traversal

      if (
        !file.startsWith(
          publicRoot
        )
      ) {

        return send(
          res,
          403,
          'Forbidden'
        );
      }


      if (
        !fs.existsSync(file) ||
        fs.statSync(file).isDirectory()
      ) {

        return send(
          res,
          404,
          'Not found'
        );
      }


      return send(
        res,
        200,
        fs.readFileSync(file),
        mime[
          path.extname(file)
        ] ||
          'application/octet-stream'
      );


    } catch (e) {

      console.error(e);


      return send(
        res,
        500,
        JSON.stringify({
          error:
            e.message
        }),
        'application/json'
      );
    }
  }
);


// ======================================================
// START SERVER
// ======================================================

server.listen(
  port,
  () => {
    console.log(
      `SEO Tracker ready: http://localhost:${port}`
    );
  }
);