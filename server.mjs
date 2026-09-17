import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
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
  getOverviewForOAuth
} from './lib.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadEnv() {
  const f = path.join(__dirname, '.env');
  if (!fs.existsSync(f)) return;
  for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m || process.env[m[1]]) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    process.env[m[1]] = v;
  }
}
loadEnv();

const port = Number(process.env.PORT || 3000);
const mime = {
  '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.json':'application/json',
  '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.ico':'image/x-icon'
};

function send(res, status, body, type='text/plain', extra={}) {
  res.writeHead(status, {'content-type': type, 'cache-control':'no-store', ...extra});
  res.end(body);
}

function cookieValue(req, name) {
  const cookies = String(req.headers.cookie || '').split(';');
  for (const c of cookies) {
    const [k, ...rest] = c.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return '';
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://${req.headers.host}`);

    if (u.pathname === '/auth/google') {
      const {url, stateCookie} = googleLoginUrl();
      return send(res, 302, '', 'text/plain', {
        'location': url,
        'set-cookie': `oauth_state=${encodeURIComponent(stateCookie)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`
      });
    }

    if (u.pathname === '/oauth2callback') {
      const stateCookie = cookieValue(req, 'oauth_state');
      const result = await handleGoogleCallback(u.searchParams.get('code'), u.searchParams.get('state'), stateCookie);
      return send(res, 302, '', 'text/plain', {
        'location': '/',
        'set-cookie': [
          `seo_auth=${encodeURIComponent(result.authCookie)}; HttpOnly; Secure=${u.protocol === 'https:'}; SameSite=Lax; Path=/; Max-Age=2592000`,
          'oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
        ]
      });
    }

    if (u.pathname === '/auth/logout' && req.method === 'POST') {
      return send(res, 204, '', 'text/plain', {
        'set-cookie': clearAuthCookie()
      });
    }

    if (u.pathname === '/api/session') {
      const user = await getAuthenticatedUser(cookieValue(req, 'seo_auth'));
      return send(res, 200, JSON.stringify({authenticated: !!user, user: user || null}), 'application/json');
    }

    if (u.pathname === '/api/sites') {
      const user = await getAuthenticatedUser(cookieValue(req, 'seo_auth'));
      if (!user) return send(res, 401, JSON.stringify({error:'Google login required'}), 'application/json');
      const sites = await getGoogleSites(user.refreshToken);
      return send(res, 200, JSON.stringify({sites}), 'application/json');
    }

    if (u.pathname === '/api/overview') {
      const site = u.searchParams.get('site') || undefined;
      const user = await getAuthenticatedUser(cookieValue(req, 'seo_auth'));
      if (user) {
        return send(res, 200, JSON.stringify(await getOverviewForOAuth(site, user.refreshToken)), 'application/json');
      }
      // Keep old demo/configured-site route available if MOCK_MODE=true.
      if (String(process.env.MOCK_MODE).toLowerCase() === 'true') {
        return send(res, 200, JSON.stringify(await getOverview(site)), 'application/json');
      }
      return send(res, 401, JSON.stringify({error:'Google login required'}), 'application/json');
    }

    if (u.pathname === '/api/pagespeed') {
      const selected = u.searchParams.get('url') || process.env.GSC_SITE_URL;
      const d = await pageSpeed(selected);
      return send(res, 200, JSON.stringify(d), 'application/json');
    }

    if (u.pathname === '/api/crawl') {
      const selected = u.searchParams.get('url') || process.env.GSC_SITE_URL;
      const d = await crawlSite(selected);
      return send(res, 200, JSON.stringify(d), 'application/json');
    }

    let p = u.pathname === '/' ? '/index.html' : u.pathname;
    p = path.normalize(p).replace(/^([.][.][\\/])+/, '');
    const publicRoot = path.join(__dirname, 'public');
    const file = path.join(publicRoot, p);
    if (!file.startsWith(publicRoot)) return send(res, 403, 'Forbidden');
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found');
    return send(res, 200, fs.readFileSync(file), mime[path.extname(file)] || 'application/octet-stream');
  } catch (e) {
    console.error(e);
    return send(res, 500, JSON.stringify({error:e.message}), 'application/json');
  }
});

server.listen(port, () => console.log(`SEO Tracker ready: http://localhost:${port}`));
