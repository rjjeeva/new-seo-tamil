import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function envBool(v){ return String(v||'').toLowerCase()==='true'; }
function dateString(d){ return d.toISOString().slice(0,10); }

function b64url(input){
  return Buffer.from(input).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

function b64urlDecode(input){
  return Buffer.from(String(input).replace(/-/g,'+').replace(/_/g,'/'), 'base64');
}

function secretKey(){
  return crypto.createHash('sha256')
    .update(process.env.SESSION_SECRET || 'change-this-local-session-secret')
    .digest();
}

function encryptJson(obj){
  const iv=crypto.randomBytes(12), key=secretKey();
  const cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
  const enc=Buffer.concat([
    cipher.update(JSON.stringify(obj),'utf8'),
    cipher.final()
  ]);
  const tag=cipher.getAuthTag();
  return `${b64url(iv)}.${b64url(tag)}.${b64url(enc)}`;
}

function decryptJson(raw){
  try{
    const [a,b,c]=String(raw||'').split('.');
    if(!a||!b||!c) return null;

    const decipher=crypto.createDecipheriv(
      'aes-256-gcm',
      secretKey(),
      b64urlDecode(a)
    );

    decipher.setAuthTag(b64urlDecode(b));

    return JSON.parse(
      Buffer.concat([
        decipher.update(b64urlDecode(c)),
        decipher.final()
      ]).toString('utf8')
    );
  }catch{
    return null;
  }
}


/* =========================================================
   GOOGLE OAUTH
========================================================= */

function oauthConfig(){
  const clientId=process.env.GOOGLE_CLIENT_ID;
  const clientSecret=process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri=process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/oauth2callback';

  if(!clientId || !clientSecret){
    throw new Error(
      'GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET is missing in .env'
    );
  }

  return {
    clientId,
    clientSecret,
    redirectUri
  };
}


export function googleLoginUrl(){
  const {clientId,redirectUri}=oauthConfig();

  const state=crypto.randomBytes(24).toString('hex');

  const params=new URLSearchParams({
    client_id:clientId,
    redirect_uri:redirectUri,
    response_type:'code',
    access_type:'offline',
    prompt:'consent',
    scope:'https://www.googleapis.com/auth/webmasters.readonly openid email profile',
    state
  });

  return {
    url:`https://accounts.google.com/o/oauth2/v2/auth?${params}`,
    stateCookie:state
  };
}


async function exchangeCode(code){
  if(!code){
    throw new Error(
      'Google OAuth callback did not contain an authorization code.'
    );
  }

  const {clientId,clientSecret,redirectUri}=oauthConfig();

  const res=await fetch(
    'https://oauth2.googleapis.com/token',
    {
      method:'POST',
      headers:{
        'content-type':'application/x-www-form-urlencoded'
      },
      body:new URLSearchParams({
        code,
        client_id:clientId,
        client_secret:clientSecret,
        redirect_uri:redirectUri,
        grant_type:'authorization_code'
      }).toString()
    }
  );

  const data=await res.json();

  if(!res.ok){
    throw new Error(
      `Google OAuth token ${res.status}: ${
        data.error_description ||
        data.error ||
        JSON.stringify(data)
      }`
    );
  }

  return data;
}


async function fetchUser(accessToken){
  const res=await fetch(
    'https://openidconnect.googleapis.com/v1/userinfo',
    {
      headers:{
        authorization:`Bearer ${accessToken}`
      }
    }
  );

  if(!res.ok) return {};

  return await res.json();
}


export async function handleGoogleCallback(code,state,stateCookie){
  if(!state || !stateCookie || state !== stateCookie){
    throw new Error(
      'Invalid OAuth state. Please try signing in again.'
    );
  }

  const token=await exchangeCode(code);

  if(!token.refresh_token){
    throw new Error(
      'Google did not return a refresh token. Please sign in again with consent.'
    );
  }

  const user=await fetchUser(token.access_token);

  const payload={
    refreshToken:token.refresh_token,
    user:{
      name:user.name||user.given_name||'Google User',
      email:user.email||'',
      picture:user.picture||''
    },
    createdAt:Date.now()
  };

  return {
    authCookie:encryptJson(payload)
  };
}


export async function getAuthenticatedUser(cookie){
  const data=decryptJson(cookie);

  if(!data?.refreshToken) return null;

  return data;
}


export function clearAuthCookie(){
  return 'seo_auth=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0';
}


/* =========================================================
   GOOGLE ACCESS TOKEN
========================================================= */

async function accessTokenFromRefresh(refreshToken){
  const {clientId,clientSecret}=oauthConfig();

  const res=await fetch(
    'https://oauth2.googleapis.com/token',
    {
      method:'POST',
      headers:{
        'content-type':'application/x-www-form-urlencoded'
      },
      body:new URLSearchParams({
        client_id:clientId,
        client_secret:clientSecret,
        refresh_token:refreshToken,
        grant_type:'refresh_token'
      }).toString()
    }
  );

  const data=await res.json();

  if(!res.ok){
    throw new Error(
      `Google refresh ${res.status}: ${
        data.error_description ||
        data.error ||
        JSON.stringify(data)
      }`
    );
  }

  return data.access_token;
}


/* =========================================================
   GOOGLE SEARCH CONSOLE SITES
========================================================= */

export async function getGoogleSites(refreshToken){
  const token=await accessTokenFromRefresh(refreshToken);

  const res=await fetch(
    'https://www.googleapis.com/webmasters/v3/sites',
    {
      headers:{
        authorization:`Bearer ${token}`
      }
    }
  );

  if(!res.ok){
    throw new Error(
      `GSC sites.list ${res.status}: ${await res.text()}`
    );
  }

  const data=await res.json();

  return (data.siteEntry||[])
    .map(x=>({
      name:hostOf(x.siteUrl),
      url:x.siteUrl,
      permissionLevel:x.permissionLevel||''
    }))
    .filter(
      x=>x.permissionLevel &&
      x.permissionLevel!=='siteUnverifiedUser'
    );
}


/* =========================================================
   GOOGLE SEARCH CONSOLE QUERY
========================================================= */

export async function gscQuery({
  startDate,
  endDate,
  dimensions=[],
  rowLimit=1000,
  searchType='web',
  dataState='final',
  dimensionFilterGroups=[],
  site,
  refreshToken
}){
  if(!site){
    throw new Error('GSC site is missing');
  }

  const token=await accessTokenFromRefresh(refreshToken);

  const endpoint=
    `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(site)}/searchAnalytics/query`;

  const body={
    startDate,
    endDate,
    dimensions,
    rowLimit,
    searchType,
    dataState
  };

  if(dimensionFilterGroups.length){
    body.dimensionFilterGroups=dimensionFilterGroups;
  }

  const res=await fetch(
    endpoint,
    {
      method:'POST',
      headers:{
        authorization:`Bearer ${token}`,
        'content-type':'application/json'
      },
      body:JSON.stringify(body)
    }
  );

  if(!res.ok){
    throw new Error(
      `GSC API ${res.status}: ${await res.text()}`
    );
  }

  return (await res.json()).rows||[];
}


/* =========================================================
   AGGREGATE GSC ROWS
========================================================= */

export function aggregateRows(rows){
  const clicks=rows.reduce(
    (s,r)=>s+(r.clicks||0),
    0
  );

  const impressions=rows.reduce(
    (s,r)=>s+(r.impressions||0),
    0
  );

  const ctr=
    impressions
      ? clicks/impressions*100
      : 0;

  const position=
    impressions
      ? rows.reduce(
          (s,r)=>
            s+(r.position||0)*(r.impressions||0),
          0
        )/impressions
      : 0;

  return {
    clicks,
    impressions,
    ctr,
    position
  };
}


export async function gscQueryWithToken(
  refreshToken,
  options
){
  return gscQuery({
    ...options,
    refreshToken
  });
}


/* =========================================================
   PAGESPEED
========================================================= */

export async function pageSpeed(url){
  const u=new URL(
    'https://www.googleapis.com/pagespeedonline/v5/runPagespeed'
  );

  u.searchParams.set('url',url);
  u.searchParams.set('strategy','mobile');

  for(
    const c of [
      'performance',
      'seo',
      'accessibility',
      'best-practices'
    ]
  ){
    u.searchParams.append('category',c);
  }

  if(process.env.PAGESPEED_API_KEY){
    u.searchParams.set(
      'key',
      process.env.PAGESPEED_API_KEY
    );
  }

  const res=await fetch(u);

  if(!res.ok){
    throw new Error(
      `PageSpeed ${res.status}: ${await res.text()}`
    );
  }

  const j=await res.json();

  const c=j.lighthouseResult?.categories||{};
  const audits=j.lighthouseResult?.audits||{};

  return {
    performance:Math.round(
      (c.performance?.score||0)*100
    ),

    seo:Math.round(
      (c.seo?.score||0)*100
    ),

    accessibility:Math.round(
      (c.accessibility?.score||0)*100
    ),

    bestPractices:Math.round(
      (c['best-practices']?.score||0)*100
    ),

    fcp:
      audits['first-contentful-paint']?.displayValue||
      '—',

    lcp:
      audits['largest-contentful-paint']?.displayValue||
      '—',

    cls:
      audits['cumulative-layout-shift']?.displayValue||
      '—',

    tbt:
      audits['total-blocking-time']?.displayValue||
      '—'
  };
}


/* =========================================================
   WEBSITE CRAWLER
========================================================= */

export async function crawlSite(site){
  const base=new URL(site);

  const out={
    robots:false,
    sitemap:false,
    https:base.protocol==='https:',
    title:false,
    description:false,
    h1:0,
    canonical:false,
    images:0,
    imagesMissingAlt:0,
    status:0
  };

  try{
    const r=await fetch(
      base,
      {
        redirect:'follow',
        headers:{
          'user-agent':'SEO-Pulse/3.0'
        }
      }
    );

    out.status=r.status;

    const html=await r.text();

    out.title=
      /<title[^>]*>[^<]+<\/title>/i.test(html);

    out.description=
      /<meta[^>]+name=["']description["'][^>]*content=["'][^"']+/i.test(html);

    out.h1=
      (html.match(/<h1\b/gi)||[]).length;

    out.canonical=
      /<link[^>]+rel=["']canonical["']/i.test(html);

    out.images=
      (html.match(/<img\b/gi)||[]).length;

    out.imagesMissingAlt=
      (
        html.match(
          /<img(?![^>]*\balt=["'][^"']*["'])[^>]*>/gi
        )||[]
      ).length;

  }catch(e){
    out.error=e.message;
  }

  try{
    const r=await fetch(
      new URL('/robots.txt',base)
    );

    out.robots=r.ok;
  }catch{}

  try{
    const r=await fetch(
      new URL('/sitemap.xml',base)
    );

    out.sitemap=r.ok;
  }catch{}

  const checks=[
    out.https,
    out.status>=200&&out.status<400,
    out.title,
    out.description,
    out.h1>0,
    out.canonical,
    out.robots,
    out.sitemap,
    out.imagesMissingAlt===0
  ];

  out.health=Math.round(
    checks.filter(Boolean).length/
    checks.length*
    100
  );

  return out;
}


/* =========================================================
   GOOGLE SEARCH CONSOLE OVERVIEW
========================================================= */

export async function getOverviewForOAuth(
  siteOverride,
  refreshToken
){
  const site=siteOverride;

  if(!site){
    throw new Error(
      'Select a Search Console property first.'
    );
  }

  const end=new Date();
  end.setDate(end.getDate()-2);

  const start=new Date(end);
  start.setDate(end.getDate()-179);

  const s=dateString(start);
  const e=dateString(end);

  const errors=[];

  let trend=[];
  let keywords=[];
  let pages=[];
  let countries=[];
  let searchAppearance=[];

  try{
    const rows=await gscQueryWithToken(
      refreshToken,
      {
        startDate:s,
        endDate:e,
        dimensions:['date'],
        rowLimit:1000,
        site
      }
    );

    trend=rows.map(
      r=>[
        r.keys?.[0],
        Math.round(r.clicks||0)
      ]
    );

  }catch(err){
    errors.push(
      `Trend: ${err.message}`
    );
  }


  try{
    const rows=await gscQueryWithToken(
      refreshToken,
      {
        startDate:s,
        endDate:e,
        dimensions:['query'],
        rowLimit:1000,
        site
      }
    );

    keywords=rows
      .slice(0,10)
      .map(
        r=>[
          r.keys?.[0]||'',
          +(r.position||0).toFixed(1),
          Math.round(r.clicks||0),
          Math.round(r.impressions||0)
        ]
      );

  }catch(err){
    errors.push(
      `Keywords: ${err.message}`
    );
  }


  try{
    const rows=await gscQueryWithToken(
      refreshToken,
      {
        startDate:s,
        endDate:e,
        dimensions:['page'],
        rowLimit:1000,
        site
      }
    );

    pages=rows
      .slice(0,10)
      .map(
        r=>[
          r.keys?.[0]||'',
          Math.round(r.clicks||0),
          Math.round(r.impressions||0)
        ]
      );

  }catch(err){
    errors.push(
      `Pages: ${err.message}`
    );
  }


  try{
    const rows=await gscQueryWithToken(
      refreshToken,
      {
        startDate:s,
        endDate:e,
        dimensions:['country'],
        rowLimit:1000,
        site
      }
    );

    const total=
      rows.reduce(
        (a,r)=>a+(r.impressions||0),
        0
      )||1;

    countries=rows
      .slice(0,5)
      .map(
        r=>[
          r.keys?.[0]||'',
          Math.round(
            (r.impressions||0)/
            total*
            100
          )
        ]
      );

  }catch(err){
    errors.push(
      `Countries: ${err.message}`
    );
  }


  try{
    searchAppearance=
      await gscQueryWithToken(
        refreshToken,
        {
          startDate:s,
          endDate:e,
          dimensions:['searchAppearance'],
          rowLimit:1000,
          site
        }
      );

  }catch(err){
    errors.push(
      `Search appearance: ${err.message}`
    );
  }


  let summaryRows=[];

  try{
    summaryRows=
      await gscQueryWithToken(
        refreshToken,
        {
          startDate:s,
          endDate:e,
          dimensions:[],
          rowLimit:1,
          site
        }
      );

  }catch(err){
    errors.push(
      `Summary: ${err.message}`
    );
  }


  const a=aggregateRows(summaryRows);

  const aiRows=
    searchAppearance.filter(
      r=>/AI|GENERATIVE/i.test(
        (r.keys||[]).join(' ')
      )
    );

  const ai=aggregateRows(aiRows);

  let pagespeed={
    performance:null,
    seo:null,
    accessibility:null,
    bestPractices:null
  };

  let crawl={
    health:null
  };


  try{
    pagespeed=await pageSpeed(site);
  }catch(err){
    errors.push(
      `PageSpeed: ${err.message}`
    );
  }


  try{
    crawl=await crawlSite(site);
  }catch(err){
    errors.push(
      `Crawler: ${err.message}`
    );
  }


  return {
    source:'gsc',
    site,

    clicks:Math.round(a.clicks),

    impressions:Math.round(
      a.impressions
    ),

    ctr:+a.ctr.toFixed(2),

    position:+a.position.toFixed(1),

    trend,
    keywords,
    pages,
    countries,

    backlinks:{
      total:null,
      domains:null,
      follow:null,
      nofollow:null,
      status:
        'Connect a backlink provider for live backlink index data.'
    },

    ai:{
      impressions:Math.round(
        ai.impressions
      ),

      clicks:Math.round(
        ai.clicks
      ),

      ctr:+ai.ctr.toFixed(2),

      status:
        aiRows.length
          ? 'Detected AI/Generative search-appearance rows'
          : 'No AI search-appearance rows returned for this property/date range.'
    },

    pagespeed,
    crawl,

    ga4:{
      sessions:null
    },

    errors
  };
}


/* =========================================================
   BING WEBMASTER OAUTH
========================================================= */

/*
 * Bing OAuth flow:
 *
 * BING_CLIENT_ID
 * BING_CLIENT_SECRET
 * BING_REFRESH_TOKEN
 * BING_SITE_URL
 *
 * Refresh token -> Access token -> Bing Webmaster API
 */

async function bingAccessToken(){

  const clientId=
    process.env.BING_CLIENT_ID;

  const clientSecret=
    process.env.BING_CLIENT_SECRET;

  const refreshToken=
    process.env.BING_REFRESH_TOKEN;


  if(
    !clientId ||
    !clientSecret ||
    !refreshToken
  ){
    throw new Error(
      'BING_CLIENT_ID / BING_CLIENT_SECRET / BING_REFRESH_TOKEN is missing in .env'
    );
  }


  const res=await fetch(
    'https://www.bing.com/webmasters/oauth/token',
    {
      method:'POST',

      headers:{
        'content-type':
          'application/x-www-form-urlencoded'
      },

      body:new URLSearchParams({
        client_id:clientId,
        client_secret:clientSecret,
        refresh_token:refreshToken,
        grant_type:'refresh_token'
      }).toString()
    }
  );


  const data=await res.json();


  if(!res.ok){
    throw new Error(
      `Bing OAuth token ${res.status}: ${
        data.error_description ||
        data.error ||
        JSON.stringify(data)
      }`
    );
  }


  if(!data.access_token){
    throw new Error(
      'Bing OAuth did not return an access token.'
    );
  }


  return data.access_token;
}


/* =========================================================
   BING RANK & TRAFFIC
========================================================= */

export async function getBingOverview(
  siteOverride
){

  const site=
    siteOverride ||
    process.env.BING_SITE_URL;


  if(!site){
    throw new Error(
      'BING_SITE_URL is missing.'
    );
  }


  const accessToken=
    await bingAccessToken();


  const endpoint=
    'https://www.bing.com/webmaster/api.svc/json/GetRankAndTrafficStats';


  const url=new URL(endpoint);

  url.searchParams.set(
    'siteUrl',
    site
  );


  const res=await fetch(
    url,
    {
      method:'GET',

      headers:{
        authorization:
          `Bearer ${accessToken}`,

        accept:
          'application/json'
      }
    }
  );


  if(!res.ok){
    throw new Error(
      `Bing API ${res.status}: ${await res.text()}`
    );
  }


  const json=await res.json();


  const rawRows=
    Array.isArray(json?.d)
      ? json.d
      : [];


  /*
   * Bing's older JSON response can return
   * Microsoft-style date strings such as:
   *
   * /Date(1316156400000-0700)/
   *
   * Convert those into YYYY-MM-DD.
   */

  const rows=
    rawRows.map(row=>{

      let date='';

      if(
        typeof row.Date==='string'
      ){

        const match=
          row.Date.match(
            /\/Date\((\d+)/
          );

        if(match){

          const timestamp=
            Number(match[1]);

          if(!Number.isNaN(timestamp)){

            date=
              new Date(timestamp)
                .toISOString()
                .slice(0,10);
          }

        }else{

          const parsed=
            new Date(row.Date);

          if(!Number.isNaN(parsed.getTime())){
            date=
              parsed
                .toISOString()
                .slice(0,10);
          }
        }
      }


      return {
        date,

        clicks:
          Number(
            row.Clicks || 0
          ),

        impressions:
          Number(
            row.Impressions || 0
          )
      };

    });


  const clicks=
    rows.reduce(
      (sum,row)=>
        sum + row.clicks,
      0
    );


  const impressions=
    rows.reduce(
      (sum,row)=>
        sum + row.impressions,
      0
    );


  const ctr=
    impressions > 0
      ? clicks / impressions * 100
      : 0;


  return {

    source:'bing',

    site,

    clicks:
      Math.round(clicks),

    impressions:
      Math.round(impressions),

    ctr:
      Number(
        ctr.toFixed(2)
      ),

    trend:
      rows.map(row=>[
        row.date,
        Math.round(row.clicks)
      ]),

    rows,

    errors:[]
  };
}



/* =========================================================
   FIXED-SITE LIVE JSON COLLECTOR
========================================================= */

const LIB_DIR = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(LIB_DIR, 'data');
const LIVE_JSON_PATH = path.join(DATA_DIR, 'regionsecurityguarding.json');
const FIXED_SITE = 'https://regionsecurityguarding.co.uk/';

function unavailable(reason){
  return {status:'unavailable', reason};
}

function hostOf(value){
  const raw=String(value||'').trim();
  if(raw.toLowerCase().startsWith('sc-domain:')){
    return raw.slice('sc-domain:'.length).replace(/^www\./,'').toLowerCase();
  }
  try{return new URL(raw).hostname.replace(/^www\./,'').toLowerCase();}
  catch{return '';}
}

async function resolveFixedGscProperty(refreshToken){
  if(!refreshToken) return null;
  const sites=await getGoogleSites(refreshToken);
  const target=hostOf(FIXED_SITE);
  const exact=sites.find(s=>s.url===FIXED_SITE);
  if(exact) return exact.url;
  const match=sites.find(s=>hostOf(s.url)===target);
  return match?.url || null;
}

async function collectGscLive(refreshToken, site){
  if(!refreshToken) return {status:'unavailable', reason:'Google Search Console login is required.'};
  if(!site) return {status:'unavailable', reason:'No Search Console property matching regionsecurityguarding.co.uk was found.'};

  const end=new Date();
  end.setDate(end.getDate()-2);
  const start=new Date(end);
  start.setDate(end.getDate()-179);
  const s=dateString(start), e=dateString(end);
  const errors=[];

  async function q(dimensions,rowLimit=1000){
    return gscQueryWithToken(refreshToken,{startDate:s,endDate:e,dimensions,rowLimit,site});
  }

  let summary=[], trend=[], keywords=[], pages=[], countries=[], searchAppearance=[];
  try{summary=await q([] ,1);}catch(e){errors.push(`Summary: ${e.message}`);}
  try{trend=await q(['date'],1000);}catch(e){errors.push(`Trend: ${e.message}`);}
  try{keywords=await q(['query'],1000);}catch(e){errors.push(`Keywords: ${e.message}`);}
  try{pages=await q(['page'],1000);}catch(e){errors.push(`Pages: ${e.message}`);}
  try{countries=await q(['country'],1000);}catch(e){errors.push(`Countries: ${e.message}`);}
  try{searchAppearance=await q(['searchAppearance'],1000);}catch(e){errors.push(`Search appearance: ${e.message}`);}

  const a=aggregateRows(summary);
  const countryTotal=countries.reduce((n,r)=>n+(r.impressions||0),0)||1;

  return {
    status: errors.length && !summary.length ? 'partial' : 'live',
    property: site,
    dateRange:{start:s,end:e},
    clicks:Math.round(a.clicks),
    impressions:Math.round(a.impressions),
    ctr:+a.ctr.toFixed(2),
    averagePosition:+a.position.toFixed(1),
    trend:trend.map(r=>({date:r.keys?.[0]||'',clicks:Math.round(r.clicks||0),impressions:Math.round(r.impressions||0),ctr:+((r.ctr||0)*100).toFixed(2),position:+(r.position||0).toFixed(1)})),
    keywords:keywords.map(r=>({query:r.keys?.[0]||'',clicks:Math.round(r.clicks||0),impressions:Math.round(r.impressions||0),ctr:+((r.ctr||0)*100).toFixed(2),position:+(r.position||0).toFixed(1)})),
    pages:pages.map(r=>({url:r.keys?.[0]||'',clicks:Math.round(r.clicks||0),impressions:Math.round(r.impressions||0),ctr:+((r.ctr||0)*100).toFixed(2),position:+(r.position||0).toFixed(1)})),
    countries:countries.map(r=>({country:r.keys?.[0]||'',clicks:Math.round(r.clicks||0),impressions:Math.round(r.impressions||0),share:+((r.impressions||0)/countryTotal*100).toFixed(2)})),
    searchAppearance:searchAppearance.map(r=>({type:r.keys?.[0]||'',clicks:Math.round(r.clicks||0),impressions:Math.round(r.impressions||0),ctr:+((r.ctr||0)*100).toFixed(2),position:+(r.position||0).toFixed(1)})),
    errors
  };
}

export async function collectLiveSeoData({refreshToken=null}={}){
  const site=FIXED_SITE;
  const collectedAt=new Date().toISOString();
  const errors=[];

  let gscProperty=null;
  try{gscProperty=await resolveFixedGscProperty(refreshToken);}catch(e){errors.push(`GSC property discovery: ${e.message}`);}

  let searchConsole;
  try{searchConsole=await collectGscLive(refreshToken,gscProperty);}catch(e){searchConsole=unavailable(e.message);errors.push(`GSC: ${e.message}`);}

  let pageSpeedData;
  try{pageSpeedData=await pageSpeed(site);}catch(e){pageSpeedData=unavailable(e.message);errors.push(`PageSpeed: ${e.message}`);}

  let crawlData;
  try{crawlData=await crawlSite(site);}catch(e){crawlData=unavailable(e.message);errors.push(`Crawler: ${e.message}`);}

  let bingData;
  try{bingData=await getBingOverview(site);}catch(e){bingData=unavailable(e.message);errors.push(`Bing: ${e.message}`);}

  return {
    site:{url:site,domain:hostOf(site),lastUpdated:collectedAt},
    overview: searchConsole?.status==='live' ? {
      clicks:searchConsole.clicks,
      impressions:searchConsole.impressions,
      ctr:searchConsole.ctr,
      averagePosition:searchConsole.averagePosition
    } : unavailable('Google Search Console data is unavailable.'),
    organicSearch: searchConsole,
    keywords: searchConsole?.keywords || [],
    pages: searchConsole?.pages || [],
    countries: searchConsole?.countries || [],
    searchAppearance: searchConsole?.searchAppearance || [],
    technicalSeo: crawlData,
    pageSpeed: pageSpeedData,
    bingWebmaster: bingData,
    backlinks: unavailable('A backlink index provider is required for complete external backlink data.'),
    ga4: unavailable('Google Analytics Data API is not connected.'),
    aiVisibility: unavailable('A real AI visibility/search provider is required.'),
    collectionErrors:errors
  };
}

export async function saveLiveSeoJson(data){
  await fs.mkdir(DATA_DIR,{recursive:true});
  await fs.writeFile(LIVE_JSON_PATH,JSON.stringify(data,null,2),'utf8');
  return LIVE_JSON_PATH;
}

/* =========================================================
   LEGACY CONFIGURED-SITE HELPERS
   Retained for MOCK_MODE / demo compatibility.
========================================================= */

export function getSites(){

  const raw=
    process.env.GSC_SITES_JSON;


  if(raw){

    try{

      const parsed=
        JSON.parse(raw);


      if(Array.isArray(parsed)){

        return parsed
          .map(
            (x,i)=>({
              name:
                x.name ||
                new URL(x.url).hostname,

              url:x.url
            })
          )
          .filter(
            x=>x.url
          );
      }

    }catch{}
  }


  const legacy=
    process.env.GSC_SITE_URL;


  return legacy
    ? [{
        name:new URL(legacy).hostname,
        url:legacy
      }]
    : [];
}


export function isConfiguredSite(site){

  return getSites()
    .some(
      x=>x.url===site
    );
}


export async function getOverview(
  siteOverride
){

  if(
    envBool(
      process.env.MOCK_MODE
    )
  ){

    return {
      source:'demo',

      site:
        siteOverride ||
        process.env.GSC_SITE_URL ||
        'regionsecurityguarding.co.uk',

      clicks:699,

      impressions:30200,

      ctr:2.3,

      position:26,

      trend:[
        ['Apr',420],
        ['May',570],
        ['Jun',910],
        ['Jul',780],
        ['Aug',610],
        ['Sep',760]
      ],

      countries:[
        ['gbr',72],
        ['usa',12],
        ['ind',4],
        ['can',3],
        ['Others',9]
      ],

      keywords:[
        [
          'region security guarding',
          1,
          170,
          1200
        ]
      ],

      pages:[
        [
          '/',
          320,
          2100
        ]
      ],

      backlinks:{
        total:null,
        domains:null,
        follow:null,
        nofollow:null,
        status:'Demo mode'
      },

      pagespeed:{
        performance:null,
        seo:null,
        accessibility:null,
        bestPractices:null
      },

      crawl:{
        health:null
      },

      ai:{
        impressions:0,
        clicks:0,
        ctr:0,
        status:'Demo mode'
      },

      errors:[]
    };
  }


  throw new Error(
    'OAuth login is required when MOCK_MODE=false.'
  );
}
