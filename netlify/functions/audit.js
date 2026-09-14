// audit.js — server-side site analyzer
// Zero dependencies. Runs on Netlify Functions (Node 18+).

const dns = require('dns').promises;
const net = require('net');

const FETCH_TIMEOUT_MS = 9000;      // main page fetch
const PROBE_TIMEOUT_MS = 3500;      // sitemap / feed / robots probes
const TOTAL_BUDGET_MS = 7800;       // stop all probing before Netlify's 10s cap

let DEADLINE = Infinity;
const msLeft = () => DEADLINE - Date.now();
const outOfTime = () => msLeft() <= 250;
const MAX_BYTES = 2_500_000;
const MAX_REDIRECTS = 5;
const UA = 'QuixSiteAudit/1.0 (+site audit tool; respects robots)';

/* ────────────────────────────────────────────
   Rate limiting (per warm instance)
   ──────────────────────────────────────────── */
const hits = new Map();
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 6;

function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < WINDOW_MS);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 500) {
    for (const [k, v] of hits) if (!v.some(t => now - t < WINDOW_MS)) hits.delete(k);
  }
  return list.length > MAX_PER_WINDOW;
}

/* ────────────────────────────────────────────
   SSRF protection
   ──────────────────────────────────────────── */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    if (p[0] >= 224) return true;
    return false;
  }
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  if (v.startsWith('fc') || v.startsWith('fd')) return true;
  if (v.startsWith('fe80')) return true;
  if (v.startsWith('::ffff:')) return isPrivateIp(v.replace('::ffff:', ''));
  return false;
}

async function assertPublicHost(hostname) {
  if (/^(localhost|.*\.local|.*\.internal)$/i.test(hostname)) {
    throw new Error('That hostname is not allowed.');
  }
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('That address is not allowed.');
    return;
  }
  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error(`Could not find a site at ${hostname}. Check the spelling.`);
  }
  if (!records.length) throw new Error(`Could not find a site at ${hostname}.`);
  for (const r of records) {
    if (isPrivateIp(r.address)) throw new Error('That address is not allowed.');
  }
}

/* ────────────────────────────────────────────
   Fetching
   ──────────────────────────────────────────── */
async function rawFetch(url, { method = 'GET' } = {}) {
  const ctrl = new AbortController();
  const budget = Math.min(FETCH_TIMEOUT_MS, Math.max(1000, msLeft()));
  const timer = setTimeout(() => ctrl.abort(), budget);
  try {
    return await fetch(url, {
      method,
      redirect: 'manual',
      signal: ctrl.signal,
      headers: { 'User-Agent': UA, 'Accept': '*/*' }
    });
  } finally {
    clearTimeout(timer);
  }
}

// Follows redirects manually so every hop gets an SSRF check.
async function safeFetch(startUrl) {
  const chain = [];
  let current = startUrl;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const u = new URL(current);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https addresses can be scanned.');
    await assertPublicHost(u.hostname);

    const started = Date.now();
    const res = await rawFetch(u.href);
    const elapsed = Date.now() - started;

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`The site returned a ${res.status} with no destination.`);
      chain.push({ url: u.href, status: res.status, to: new URL(loc, u.href).href });
      current = new URL(loc, u.href).href;
      continue;
    }

    const body = await readCapped(res);
    return { res, body, finalUrl: u.href, chain, elapsed };
  }
  throw new Error('The site redirected too many times.');
}

async function readCapped(res) {
  const reader = res.body?.getReader?.();
  if (!reader) return await res.text();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    chunks.push(value);
    if (total > MAX_BYTES) { try { reader.cancel(); } catch {} break; }
  }
  return Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
}

async function tryFetch(url) {
  if (outOfTime()) return null;
  try {
    const u = new URL(url);
    await assertPublicHost(u.hostname);
    const budget = Math.min(PROBE_TIMEOUT_MS, Math.max(500, msLeft()));
    const res = await fetch(u.href, {
      redirect: 'follow',
      headers: { 'User-Agent': UA },
      signal: AbortSignal.timeout(budget)
    });
    if (!res.ok) return null;
    const text = await readCapped(res);
    return { text, url: res.url || u.href, headers: res.headers };
  } catch {
    return null;
  }
}

// Probe several candidate URLs at once and return the first that passes `test`,
// in candidate order. Sequential probing is what blew the function timeout.
async function firstMatch(candidates, test) {
  if (outOfTime()) return null;
  const results = await Promise.all(candidates.map(c => tryFetch(c)));
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r && test(r)) return r;
  }
  return null;
}

/* ────────────────────────────────────────────
   HTML parsing helpers
   ──────────────────────────────────────────── */
const stripTags = h => h.replace(/<script[\s\S]*?<\/script>/gi, ' ')
                        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
                        .replace(/<!--[\s\S]*?-->/g, ' ')
                        .replace(/<[^>]+>/g, ' ');

const decode = s => (s || '')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&nbsp;/g, ' ')
  .replace(/\s+/g, ' ').trim();

function attr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? decode(m[2] ?? m[3] ?? m[4]) : null;
}

function metaByName(html, key, type = 'name') {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const t of tags) {
    if ((attr(t, type) || '').toLowerCase() === key.toLowerCase()) {
      return attr(t, 'content');
    }
  }
  return null;
}

function linkRel(html, rel) {
  const tags = html.match(/<link\b[^>]*>/gi) || [];
  return tags.filter(t => (attr(t, 'rel') || '').toLowerCase().split(/\s+/).includes(rel));
}

function headings(html, level) {
  const re = new RegExp(`<h${level}\\b[^>]*>([\\s\\S]*?)<\\/h${level}>`, 'gi');
  return [...html.matchAll(re)].map(m => decode(stripTags(m[1]))).filter(Boolean);
}

/* ────────────────────────────────────────────
   Analyzers
   ──────────────────────────────────────────── */
function analyzeSeo(html, finalUrl) {
  const head = (html.match(/<head[\s\S]*?<\/head>/i) || [html])[0];
  const titleM = head.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleM ? decode(stripTags(titleM[1])) : null;
  const description = metaByName(html, 'description');
  const h1s = headings(html, 1);
  const h2s = headings(html, 2);
  const h3s = headings(html, 3);

  const imgTags = html.match(/<img\b[^>]*>/gi) || [];
  const missingAlt = imgTags.filter(t => {
    const a = attr(t, 'alt');
    return a === null || a === '';
  });

  const text = decode(stripTags(html.replace(/<(nav|header|footer)[\s\S]*?<\/\1>/gi, ' ')));
  const wordCount = text ? text.split(/\s+/).filter(w => /[a-z0-9]/i.test(w)).length : 0;

  const origin = new URL(finalUrl).origin;
  const anchors = html.match(/<a\b[^>]*href[^>]*>/gi) || [];
  let internal = 0, external = 0;
  for (const a of anchors) {
    const href = attr(a, 'href');
    if (!href || /^(#|mailto:|tel:|javascript:)/i.test(href)) continue;
    try {
      const abs = new URL(href, finalUrl);
      if (abs.origin === origin) internal++; else external++;
    } catch {}
  }

  const canonicalTag = linkRel(html, 'canonical')[0];
  const canonical = canonicalTag ? attr(canonicalTag, 'href') : null;
  const schemaBlocks = (html.match(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>/gi) || []).length;
  const schemaTypes = [...html.matchAll(/"@type"\s*:\s*"([^"]+)"/g)].map(m => m[1]);

  return {
    title,
    titleLength: title ? title.length : 0,
    description,
    descriptionLength: description ? description.length : 0,
    h1s, h1Count: h1s.length, h2Count: h2s.length, h3Count: h3s.length,
    imageCount: imgTags.length,
    imagesMissingAlt: missingAlt.length,
    wordCount,
    internalLinks: internal,
    externalLinks: external,
    canonical,
    robotsMeta: metaByName(html, 'robots'),
    lang: (html.match(/<html\b[^>]*>/i) || []).length ? attr(html.match(/<html\b[^>]*>/i)[0], 'lang') : null,
    ogTitle: metaByName(html, 'og:title', 'property'),
    ogDescription: metaByName(html, 'og:description', 'property'),
    ogImage: metaByName(html, 'og:image', 'property'),
    twitterCard: metaByName(html, 'twitter:card') || metaByName(html, 'twitter:card', 'property'),
    schemaBlocks,
    schemaTypes: [...new Set(schemaTypes)].slice(0, 12),
    favicon: linkRel(html, 'icon').length > 0
  };
}

function analyzeUx(html, headers, elapsed, finalUrl, chain) {
  const viewportTag = metaByName(html, 'viewport');
  const htmlBytes = Buffer.byteLength(html, 'utf8');

  const scripts = (html.match(/<script\b[^>]*src=/gi) || []).length;
  const stylesheets = linkRel(html, 'stylesheet').length;
  const inlineStyles = (html.match(/\bstyle\s*=\s*["']/gi) || []).length;

  const imgTags = html.match(/<img\b[^>]*>/gi) || [];
  const lazyImages = imgTags.filter(t => (attr(t, 'loading') || '').toLowerCase() === 'lazy').length;
  const sizedImages = imgTags.filter(t => attr(t, 'width') && attr(t, 'height')).length;
  const modernFormats = imgTags.filter(t => /\.(webp|avif)(\?|$)/i.test(attr(t, 'src') || '')).length
    + (html.match(/<source\b[^>]*type\s*=\s*["']image\/(webp|avif)["']/gi) || []).length;

  const forms = (html.match(/<form\b/gi) || []).length;
  const bodyText = html;
  const hasTelLink = /href\s*=\s*["']tel:/i.test(bodyText);
  const hasMailLink = /href\s*=\s*["']mailto:/i.test(bodyText);
  const contactWords = /\b(contact|get a quote|request a quote|book now|schedule|call us|free estimate|get started)\b/i.test(decode(stripTags(html)));

  const ctaButtons = (html.match(/<(button|a)\b[^>]*class\s*=\s*["'][^"']*\b(btn|button|cta)\b/gi) || []).length;

  return {
    responseMs: elapsed,
    htmlKb: Math.round(htmlBytes / 1024),
    https: new URL(finalUrl).protocol === 'https:',
    redirectHops: chain.length,
    redirectChain: chain,
    viewport: viewportTag,
    mobileReady: !!viewportTag && /width\s*=\s*device-width/i.test(viewportTag),
    scripts, stylesheets, inlineStyles,
    imageCount: imgTags.length,
    lazyImages, sizedImages, modernFormats,
    forms,
    hasTelLink, hasMailLink, contactWords, ctaButtons,
    compression: headers.get('content-encoding') || null,
    cacheControl: headers.get('cache-control') || null,
    server: headers.get('server') || null,
    poweredBy: headers.get('x-powered-by') || null,
    hsts: !!headers.get('strict-transport-security'),
    xContentType: !!headers.get('x-content-type-options'),
    frameOptions: !!(headers.get('x-frame-options') || /frame-ancestors/i.test(headers.get('content-security-policy') || '')),
    csp: !!headers.get('content-security-policy')
  };
}

function detectPlatform(html, headers) {
  const sigs = [
    [/wp-content|wp-includes|\/wp-json/i, 'WordPress'],
    [/cdn\.shopify\.com|Shopify\.theme/i, 'Shopify'],
    [/static\.parastorage\.com|wix\.com/i, 'Wix'],
    [/squarespace|static1\.squarespace/i, 'Squarespace'],
    [/img1\.wsimg\.com|godaddy\.com\/websites/i, 'GoDaddy Website Builder'],
    [/cdn\.editmysite\.com|weebly/i, 'Weebly'],
    [/webflow\.com|wf-domain/i, 'Webflow'],
    [/Drupal\.settings|\/sites\/default\/files/i, 'Drupal'],
    [/Joomla|\/media\/jui\//i, 'Joomla'],
    [/_next\/static/i, 'Next.js'],
    [/bigcommerce/i, 'BigCommerce'],
    [/duda|irp\.cdn-website\.com/i, 'Duda']
  ];
  const found = sigs.filter(([re]) => re.test(html)).map(([, name]) => name);
  const gen = metaByName(html, 'generator');
  if (gen) found.push(gen.split(' ')[0]);
  const via = headers.get('x-powered-by');
  return { detected: [...new Set(found)].slice(0, 4), generator: gen, poweredBy: via };
}

/* ────────────────────────────────────────────
   Freshness: sitemap, feeds, visible dates
   ──────────────────────────────────────────── */
function parseSitemapUrls(xml) {
  return [...xml.matchAll(/<url>([\s\S]*?)<\/url>/gi)].map(m => {
    const loc = (m[1].match(/<loc>([\s\S]*?)<\/loc>/i) || [])[1];
    const mod = (m[1].match(/<lastmod>([\s\S]*?)<\/lastmod>/i) || [])[1];
    return { loc: decode(loc), lastmod: mod ? decode(mod) : null };
  }).filter(u => u.loc);
}

async function analyzeFreshness(origin, html, headers) {
  const out = {
    sitemapFound: false, sitemapUrl: null, pageCount: 0,
    withLastmod: 0, newestLastmod: null, oldestLastmod: null,
    staleOverYear: 0, updatedLast90: 0,
    lastModifiedHeader: headers.get('last-modified') || null,
    robotsTxt: false, sitemapInRobots: null, notes: []
  };

  const robots = await tryFetch(`${origin}/robots.txt`);
  const candidates = [];
  if (robots && !/<html/i.test(robots.text)) {
    out.robotsTxt = true;
    const refs = [...robots.text.matchAll(/^\s*sitemap:\s*(\S+)/gim)].map(m => m[1]);
    if (refs.length) { out.sitemapInRobots = refs[0]; candidates.push(...refs); }
  }
  candidates.push(`${origin}/sitemap.xml`, `${origin}/sitemap_index.xml`, `${origin}/sitemap-index.xml`);

  const hit = await firstMatch(
    [...new Set(candidates)].slice(0, 4),
    r => /<(urlset|sitemapindex)/i.test(r.text)
  );
  let xml = null;
  if (hit) { xml = hit.text; out.sitemapUrl = hit.url; out.sitemapFound = true; }

  let urls = [];
  if (xml) {
    if (/<sitemapindex/i.test(xml)) {
      const children = [...xml.matchAll(/<sitemap>[\s\S]*?<loc>([\s\S]*?)<\/loc>/gi)].map(m => decode(m[1]));
      const take = children.slice(0, 3);
      out.notes.push(`Sitemap index with ${children.length} child sitemaps; ${take.length} scanned.`);
      const kids = await Promise.all(take.map(c => tryFetch(c)));
      for (const r of kids) if (r) urls.push(...parseSitemapUrls(r.text));
    } else {
      urls = parseSitemapUrls(xml);
    }
  }

  const now = Date.now();
  const dates = [];
  for (const u of urls) {
    if (!u.lastmod) continue;
    const t = Date.parse(u.lastmod);
    if (!isNaN(t)) dates.push(t);
  }
  out.pageCount = urls.length;
  out.withLastmod = dates.length;
  if (dates.length) {
    dates.sort((a, b) => a - b);
    out.oldestLastmod = new Date(dates[0]).toISOString();
    out.newestLastmod = new Date(dates[dates.length - 1]).toISOString();
    out.staleOverYear = dates.filter(t => now - t > 365 * 864e5).length;
    out.updatedLast90 = dates.filter(t => now - t < 90 * 864e5).length;
  }

  // Fallback: copyright year in footer
  const years = [...decode(stripTags(html)).matchAll(/(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-–]\s*)?(\d{4})/gi)]
    .map(m => parseInt(m[1], 10)).filter(y => y > 2000 && y <= new Date().getFullYear() + 1);
  out.copyrightYear = years.length ? Math.max(...years) : null;

  return out;
}

function parseFeed(xml) {
  const items = [];
  for (const m of xml.matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const b = m[1];
    items.push({
      title: decode(stripTags((b.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || '')),
      date: (b.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || [])[1] || null,
      link: decode((b.match(/<link>([\s\S]*?)<\/link>/i) || [])[1] || '')
    });
  }
  for (const m of xml.matchAll(/<entry>([\s\S]*?)<\/entry>/gi)) {
    const b = m[1];
    const linkTag = (b.match(/<link\b[^>]*>/i) || [])[0] || '';
    items.push({
      title: decode(stripTags((b.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '')),
      date: (b.match(/<(?:updated|published)>([\s\S]*?)<\/(?:updated|published)>/i) || [])[1] || null,
      link: attr(linkTag, 'href') || ''
    });
  }
  return items.map(i => ({ ...i, ts: i.date ? Date.parse(i.date) : NaN }))
              .filter(i => !isNaN(i.ts))
              .sort((a, b) => b.ts - a.ts);
}

async function analyzeBlog(origin, html, finalUrl) {
  const out = {
    feedFound: false, feedUrl: null, blogUrlFound: null,
    postCount: 0, latestPostDate: null, latestPostTitle: null,
    daysSinceLastPost: null, postsLast90: 0, postsLast365: 0,
    averageGapDays: null, cadence: 'unknown', recentPosts: []
  };

  const candidates = [];
  for (const t of linkRel(html, 'alternate')) {
    const type = (attr(t, 'type') || '').toLowerCase();
    const href = attr(t, 'href');
    if (href && /(rss|atom|xml)/.test(type)) candidates.push(new URL(href, finalUrl).href);
  }
  candidates.push(
    `${origin}/feed`, `${origin}/rss`, `${origin}/rss.xml`, `${origin}/feed.xml`,
    `${origin}/atom.xml`, `${origin}/blog/feed`, `${origin}/blog/rss.xml`,
    `${origin}/news/feed`, `${origin}/blogs/news.atom`
  );

  let items = [];
  const feedHit = await firstMatch(
    [...new Set(candidates)].slice(0, 8),
    r => /<(rss|feed|channel)\b/i.test(r.text) && parseFeed(r.text).length > 0
  );
  if (feedHit) { items = parseFeed(feedHit.text); out.feedFound = true; out.feedUrl = feedHit.url; }

  // No feed: look for a blog section and read visible dates
  if (!items.length) {
    const blogPaths = ['/blog', '/news', '/articles', '/insights', '/blogs/news'];
    const pages = (await Promise.all(blogPaths.map(bp => tryFetch(origin + bp))))
      .filter(r => r && /<html/i.test(r.text));
    for (const r of pages) {
      out.blogUrlFound = r.url;
      const found = [];
      for (const m of r.text.matchAll(/<time\b[^>]*datetime\s*=\s*["']([^"']+)["']/gi)) found.push(Date.parse(m[1]));
      for (const m of r.text.matchAll(/"(?:datePublished|article:published_time)"\s*:\s*"([^"]+)"/gi)) found.push(Date.parse(m[1]));
      for (const m of r.text.matchAll(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},\s+(20\d{2})\b/gi)) found.push(Date.parse(m[0]));
      const valid = found.filter(t => !isNaN(t)).sort((a, b) => b - a);
      if (valid.length) {
        items = valid.map(ts => ({ ts, title: null, link: null }));
        break;
      }
    }
  }

  if (!items.length) {
    // Is there even a blog link?
    const hasBlogLink = /<a\b[^>]*href\s*=\s*["'][^"']*\/(blog|news|articles|insights)\b/i.test(html);
    out.blogLinkOnHomepage = hasBlogLink;
    return out;
  }

  const now = Date.now();
  out.postCount = items.length;
  out.latestPostDate = new Date(items[0].ts).toISOString();
  out.latestPostTitle = items[0].title || null;
  out.daysSinceLastPost = Math.floor((now - items[0].ts) / 864e5);
  out.postsLast90 = items.filter(i => now - i.ts < 90 * 864e5).length;
  out.postsLast365 = items.filter(i => now - i.ts < 365 * 864e5).length;
  out.recentPosts = items.slice(0, 5).map(i => ({
    title: i.title, link: i.link, date: new Date(i.ts).toISOString()
  }));

  if (items.length > 1) {
    const gaps = [];
    for (let i = 0; i < Math.min(items.length - 1, 10); i++) {
      gaps.push((items[i].ts - items[i + 1].ts) / 864e5);
    }
    const avg = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    out.averageGapDays = Math.round(avg);
    out.cadence = avg <= 10 ? 'weekly or better'
      : avg <= 35 ? 'roughly monthly'
      : avg <= 100 ? 'quarterly'
      : 'sporadic';
  }
  return out;
}


/* ────────────────────────────────────────────
   Domain registration (RDAP — free, no key)
   ──────────────────────────────────────────── */
function registrableDomain(hostname){
  const parts = hostname.replace(/^www\./i,'').split('.');
  if (parts.length <= 2) return parts.join('.');
  const twoLevel = /^(co|com|net|org|gov|edu|ac|or|ne|go)\.[a-z]{2}$/i;
  const last2 = parts.slice(-2).join('.');
  return twoLevel.test(last2) ? parts.slice(-3).join('.') : last2;
}

async function analyzeDomain(hostname){
  const out = {
    domain: registrableDomain(hostname), queried: false,
    registrar: null, created: null, expires: null, updated: null,
    ageYears: null, daysToExpiry: null,
    privacyProtected: null, statuses: [], nameservers: [], dnssec: null
  };
  if (outOfTime()) return out;
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(out.domain)}`, {
      redirect: 'follow',
      headers: { 'User-Agent': UA, 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(Math.min(4000, Math.max(500, msLeft())))
    });
    if (!res.ok) return out;
    const j = await res.json();
    out.queried = true;

    for (const e of (j.events || [])) {
      const d = e.eventDate;
      if (!d) continue;
      if (/registration/i.test(e.eventAction)) out.created = d;
      if (/expiration/i.test(e.eventAction)) out.expires = d;
      if (/last changed|last update of rdap/i.test(e.eventAction) && !out.updated) out.updated = d;
    }

    for (const ent of (j.entities || [])) {
      const roles = (ent.roles || []).map(r => r.toLowerCase());
      const name = (ent.vcardArray?.[1] || []).find(f => f[0] === 'fn')?.[3];
      if (roles.includes('registrar') && name) out.registrar = name;
      if (roles.includes('registrant') && name) {
        out.privacyProtected = /privacy|proxy|redacted|withheld|not disclosed|domains by/i.test(name);
      }
    }
    if (out.privacyProtected === null && /redacted|privacy/i.test(JSON.stringify(j.entities || []))) {
      out.privacyProtected = true;
    }

    out.statuses = (j.status || []).slice(0, 8);
    out.nameservers = (j.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).slice(0, 6);
    out.dnssec = typeof j.secureDNS?.delegationSigned === 'boolean' ? j.secureDNS.delegationSigned : null;

    const now = Date.now();
    if (out.created) {
      const t = Date.parse(out.created);
      if (!isNaN(t)) out.ageYears = Math.floor((now - t) / (365.25 * 864e5));
    }
    if (out.expires) {
      const t = Date.parse(out.expires);
      if (!isNaN(t)) out.daysToExpiry = Math.floor((t - now) / 864e5);
    }
  } catch {}
  return out;
}

/* ────────────────────────────────────────────
   Scoring
   ──────────────────────────────────────────── */
function scoreAudit(seo, ux, fresh, blog) {
  const findings = [];
  const add = (area, severity, label, detail) => findings.push({ area, severity, label, detail });

  // ---- SEO (35) ----
  let s = 35;
  if (!seo.title) { s -= 9; add('SEO', 'critical', 'No page title', 'Search engines have no headline to show for this page.'); }
  else if (seo.titleLength < 25 || seo.titleLength > 65) { s -= 3; add('SEO', 'warn', `Title is ${seo.titleLength} characters`, 'Aim for roughly 30 to 60 so it is not cut off in results.'); }

  if (!seo.description) { s -= 7; add('SEO', 'critical', 'No meta description', 'Google writes its own snippet instead of your sales pitch.'); }
  else if (seo.descriptionLength < 70 || seo.descriptionLength > 165) { s -= 2; add('SEO', 'warn', `Meta description is ${seo.descriptionLength} characters`, 'Around 120 to 158 reads best in search results.'); }

  if (seo.h1Count === 0) { s -= 5; add('SEO', 'critical', 'No H1 heading', 'The main topic of the page is not marked up.'); }
  else if (seo.h1Count > 1) { s -= 2; add('SEO', 'warn', `${seo.h1Count} H1 headings`, 'One main heading per page is clearer for search engines.'); }

  if (seo.wordCount < 300) { s -= 4; add('SEO', 'warn', `Only about ${seo.wordCount} words of content`, 'Thin pages rank poorly. 500+ words gives search engines something to work with.'); }
  if (!seo.canonical) { s -= 2; add('SEO', 'info', 'No canonical tag', 'Helps prevent duplicate-content confusion.'); }
  if (seo.schemaBlocks === 0) { s -= 3; add('SEO', 'warn', 'No structured data', 'Schema markup is what produces star ratings, FAQs and business info in search results.'); }
  if (!seo.ogTitle || !seo.ogImage) { s -= 2; add('SEO', 'warn', 'Incomplete social sharing tags', 'Links shared to Facebook or LinkedIn will look plain.'); }
  if (seo.imagesMissingAlt > 0) {
    const pct = Math.round((seo.imagesMissingAlt / Math.max(seo.imageCount, 1)) * 100);
    s -= Math.min(3, Math.ceil(pct / 34));
    add('SEO', pct > 50 ? 'warn' : 'info', `${seo.imagesMissingAlt} of ${seo.imageCount} images missing alt text`, 'Alt text helps image search and screen readers.');
  }
  if (!fresh.robotsTxt) { s -= 1; add('SEO', 'info', 'No robots.txt', 'Standard file telling crawlers what to index.'); }
  if (!fresh.sitemapFound) { s -= 4; add('SEO', 'critical', 'No XML sitemap found', 'Search engines have to guess which pages exist.'); }
  if (/noindex/i.test(seo.robotsMeta || '')) { s -= 12; add('SEO', 'critical', 'Page is set to noindex', 'This page is actively telling Google not to list it.'); }

  // ---- UX (30) ----
  let u = 30;
  if (!ux.https) { u -= 8; add('UX', 'critical', 'Not served over HTTPS', 'Browsers show a "Not secure" warning to every visitor.'); }
  if (!ux.mobileReady) { u -= 8; add('UX', 'critical', 'No mobile viewport tag', 'The site will not scale properly on phones, where most traffic comes from.'); }
  if (ux.responseMs > 2500) { u -= 5; add('UX', 'warn', `Server took ${(ux.responseMs / 1000).toFixed(1)}s to respond`, 'Slow first response delays everything else on the page.'); }
  else if (ux.responseMs > 1200) { u -= 2; add('UX', 'info', `Server responded in ${(ux.responseMs / 1000).toFixed(1)}s`, 'Room to improve, but not urgent.'); }
  if (ux.htmlKb > 400) { u -= 3; add('UX', 'warn', `Page HTML is ${ux.htmlKb} KB`, 'Large HTML slows down phones on cell connections.'); }
  if (ux.scripts > 25) { u -= 3; add('UX', 'warn', `${ux.scripts} external scripts`, 'Each one is another request before the page is usable.'); }
  if (ux.imageCount > 4 && ux.lazyImages === 0) { u -= 2; add('UX', 'warn', 'Images are not lazy-loaded', 'Every image downloads up front, even ones far down the page.'); }
  if (ux.imageCount > 4 && ux.sizedImages / ux.imageCount < 0.5) { u -= 2; add('UX', 'warn', 'Images missing width and height', 'Causes content to jump around while the page loads.'); }
  if (ux.imageCount > 4 && ux.modernFormats === 0) { u -= 2; add('UX', 'info', 'No WebP or AVIF images', 'Modern formats cut image weight roughly in half.'); }
  if (!ux.compression) { u -= 2; add('UX', 'warn', 'No compression detected', 'Gzip or Brotli would shrink the page significantly.'); }
  if (!ux.hasTelLink && !ux.hasMailLink && ux.forms === 0) { u -= 4; add('UX', 'critical', 'No obvious way to make contact', 'No phone link, email link or form found on the homepage.'); }
  else if (!ux.hasTelLink) { u -= 1; add('UX', 'info', 'Phone number is not tappable', 'A tel: link lets mobile visitors call in one tap.'); }
  if (ux.redirectHops > 1) { u -= 2; add('UX', 'warn', `${ux.redirectHops} redirects before the page loads`, 'Each hop adds delay and dilutes link value.'); }
  if (!ux.hsts && ux.https) { u -= 1; add('UX', 'info', 'No HSTS header', 'Forces browsers to stay on the secure version.'); }

  // ---- Freshness (20) ----
  let f = 20;
  const now = Date.now();
  if (fresh.newestLastmod) {
    const days = Math.floor((now - Date.parse(fresh.newestLastmod)) / 864e5);
    fresh.daysSinceAnyUpdate = days;
    if (days > 730) { f -= 14; add('Freshness', 'critical', `Nothing updated in about ${Math.floor(days / 365)} years`, 'Search engines favour sites that show signs of life.'); }
    else if (days > 365) { f -= 10; add('Freshness', 'critical', `Last update was ${days} days ago`, 'Over a year without changes signals an abandoned site.'); }
    else if (days > 180) { f -= 6; add('Freshness', 'warn', `Last update was ${days} days ago`, 'Worth a refresh to stay competitive.'); }
    else if (days > 90) { f -= 3; add('Freshness', 'info', `Last update was ${days} days ago`, 'Reasonable, but quarterly updates keep momentum.'); }
    if (fresh.pageCount && fresh.staleOverYear / fresh.pageCount > 0.7) {
      f -= 3;
      add('Freshness', 'warn', `${fresh.staleOverYear} of ${fresh.pageCount} pages untouched for over a year`, 'Most of the site is sitting still.');
    }
  } else {
    f -= 6;
    add('Freshness', 'warn', 'No update dates published', 'Without lastmod dates in the sitemap, crawlers cannot tell what changed.');
  }
  if (fresh.copyrightYear && fresh.copyrightYear < new Date().getFullYear() - 1) {
    f -= 2;
    add('Freshness', 'warn', `Footer copyright still says ${fresh.copyrightYear}`, 'Visitors read this as a sign the business may be closed.');
  }

  // ---- Blog (15) ----
  let b = 15;
  if (!blog.feedFound && !blog.blogUrlFound && blog.postCount === 0) {
    b -= 13;
    add('Blog', 'critical', 'No blog or news section found', 'A blog is the most reliable way to add indexable pages and rank for more searches.');
  } else if (blog.daysSinceLastPost === null) {
    b -= 8;
    add('Blog', 'warn', 'Blog found but no post dates readable', 'Publish dates help search engines judge freshness.');
  } else {
    const d = blog.daysSinceLastPost;
    if (d > 365) { b -= 11; add('Blog', 'critical', `Last blog post was ${d} days ago`, 'The blog has effectively stopped, and so has the SEO benefit.'); }
    else if (d > 180) { b -= 8; add('Blog', 'critical', `Last blog post was ${d} days ago`, 'Momentum is lost after about six months of silence.'); }
    else if (d > 90) { b -= 5; add('Blog', 'warn', `Last blog post was ${d} days ago`, 'Slipping. Monthly posting keeps rankings climbing.'); }
    else if (d > 45) { b -= 2; add('Blog', 'info', `Last blog post was ${d} days ago`, 'Active, though a tighter cadence would compound faster.'); }
    if (blog.postsLast365 > 0 && blog.postsLast365 < 4) {
      b -= 2;
      add('Blog', 'warn', `Only ${blog.postsLast365} posts in the past year`, 'Aim for at least one a month to build topical authority.');
    }
  }

  const clamp = (v, max) => Math.max(0, Math.min(max, Math.round(v)));
  const scores = {
    seo: clamp(s, 35), ux: clamp(u, 30), freshness: clamp(f, 20), blog: clamp(b, 15)
  };
  const total = scores.seo + scores.ux + scores.freshness + scores.blog;
  const grade = total >= 90 ? 'A' : total >= 80 ? 'B' : total >= 70 ? 'C' : total >= 55 ? 'D' : 'F';

  const rank = { critical: 0, warn: 1, info: 2 };
  findings.sort((a, b2) => rank[a.severity] - rank[b2.severity]);

  return {
    total, grade,
    breakdown: [
      { area: 'Search visibility', score: scores.seo, max: 35 },
      { area: 'Visitor experience', score: scores.ux, max: 30 },
      { area: 'Site freshness', score: scores.freshness, max: 20 },
      { area: 'Blog activity', score: scores.blog, max: 15 }
    ],
    findings
  };
}

/* ────────────────────────────────────────────
   Handler
   ──────────────────────────────────────────── */
exports.handler = async (event) => {
  const cors = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: cors, body: JSON.stringify({ error: 'Use POST.' }) };
  }

  const ip = event.headers['x-nf-client-connection-ip']
    || (event.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || 'unknown';
  if (rateLimited(ip)) {
    return { statusCode: 429, headers: cors, body: JSON.stringify({ error: 'Too many scans in a row. Wait a minute and try again.' }) };
  }

  let input;
  try { input = JSON.parse(event.body || '{}').url; } catch { input = null; }
  if (!input || typeof input !== 'string') {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Enter a website address to scan.' }) };
  }

  let target = input.trim();
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

  try {
    new URL(target);
  } catch {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'That does not look like a valid web address.' }) };
  }

  const started = Date.now();
  DEADLINE = started + TOTAL_BUDGET_MS;
  try {
    let result;
    try {
      result = await safeFetch(target);
    } catch (e) {
      if (/^https:/i.test(target) && /fetch failed|certificate|ENOTFOUND|ECONNREFUSED|socket/i.test(e.message)) {
        result = await safeFetch(target.replace(/^https:/i, 'http:'));
      } else {
        throw e;
      }
    }

    const { res, body, finalUrl, chain, elapsed } = result;

    if (res.status >= 400) {
      return {
        statusCode: 200, headers: cors,
        body: JSON.stringify({ error: `The site returned status ${res.status}. It may be down or blocking scanners.` })
      };
    }
    if (!/<html|<body|<head/i.test(body)) {
      return {
        statusCode: 200, headers: cors,
        body: JSON.stringify({ error: 'That address did not return a web page.' })
      };
    }

    const origin = new URL(finalUrl).origin;
    const seo = analyzeSeo(body, finalUrl);
    const ux = analyzeUx(body, res.headers, elapsed, finalUrl, chain);
    const platform = detectPlatform(body, res.headers);
    // Hard stop: if the extra lookups run long, return what we have rather than
    // letting Netlify kill the function and send the browser an empty body.
    const fallbackFresh = { sitemapFound:false, sitemapUrl:null, pageCount:0, withLastmod:0,
      newestLastmod:null, oldestLastmod:null, staleOverYear:0, updatedLast90:0,
      lastModifiedHeader:res.headers.get('last-modified')||null, robotsTxt:false,
      sitemapInRobots:null, notes:['Some checks timed out.'], copyrightYear:null };
    const fallbackBlog = { feedFound:false, feedUrl:null, blogUrlFound:null, postCount:0,
      latestPostDate:null, latestPostTitle:null, daysSinceLastPost:null, postsLast90:0,
      postsLast365:0, averageGapDays:null, cadence:'unknown', recentPosts:[] };
    const fallbackDomain = { domain:new URL(finalUrl).hostname, queried:false, registrar:null,
      created:null, expires:null, updated:null, ageYears:null, daysToExpiry:null,
      privacyProtected:null, statuses:[], nameservers:[], dnssec:null };

    const withTimeout = (promise, fallback) => Promise.race([
      promise.catch(() => fallback),
      new Promise(r => setTimeout(() => r(fallback), Math.max(500, msLeft())))
    ]);

    const [fresh, blog, domain] = await Promise.all([
      withTimeout(analyzeFreshness(origin, body, res.headers), fallbackFresh),
      withTimeout(analyzeBlog(origin, body, finalUrl), fallbackBlog),
      withTimeout(analyzeDomain(new URL(finalUrl).hostname), fallbackDomain)
    ]);
    const scored = scoreAudit(seo, ux, fresh, blog);

    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({
        requestedUrl: input,
        finalUrl,
        scannedAt: new Date().toISOString(),
        scanDurationMs: Date.now() - started,
        platform,
        score: scored,
        seo, ux, freshness: fresh, blog, domain
      })
    };
  } catch (e) {
    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({ error: e.message || 'The scan could not be completed.' })
    };
  }
};
