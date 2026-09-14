// psi.js — Google PageSpeed Insights (Lighthouse + Core Web Vitals)
// Called separately from audit.js because Lighthouse takes 10-30s.
// Requires env var PSI_API_KEY. Free, no billing, 25,000 requests/day.

const dns = require('dns').promises;
const net = require('net');

const hits = new Map();
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 4;

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

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0
      || (p[0] === 169 && p[1] === 254)
      || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
      || (p[0] === 192 && p[1] === 168)
      || (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
      || p[0] >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.replace('::ffff:', ''));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}

async function assertPublicHost(hostname) {
  if (/^(localhost|.*\.local|.*\.internal)$/i.test(hostname)) throw new Error('That hostname is not allowed.');
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('That address is not allowed.');
    return;
  }
  const recs = await dns.lookup(hostname, { all: true }).catch(() => []);
  if (!recs.length) throw new Error('Could not resolve that hostname.');
  for (const r of recs) if (isPrivateIp(r.address)) throw new Error('That address is not allowed.');
}

const pct = v => (typeof v === 'number' ? Math.round(v * 100) : null);

function readVitals(loadingExperience) {
  if (!loadingExperience || !loadingExperience.metrics) return null;
  const m = loadingExperience.metrics;
  const pick = (key, divide = 1, unit = '') => {
    const d = m[key];
    if (!d) return null;
    return {
      value: +(d.percentile / divide).toFixed(divide === 1 ? 0 : 2),
      unit,
      rating: d.category ? d.category.toLowerCase().replace(/_/g, ' ') : null
    };
  };
  return {
    overall: loadingExperience.overall_category
      ? loadingExperience.overall_category.toLowerCase().replace(/_/g, ' ')
      : null,
    lcp: pick('LARGEST_CONTENTFUL_PAINT_MS', 1000, 's'),
    inp: pick('INTERACTION_TO_NEXT_PAINT', 1, 'ms'),
    cls: pick('CUMULATIVE_LAYOUT_SHIFT_SCORE', 100, ''),
    fcp: pick('FIRST_CONTENTFUL_PAINT_MS', 1000, 's'),
    ttfb: pick('EXPERIMENTAL_TIME_TO_FIRST_BYTE', 1000, 's')
  };
}

function readOpportunities(audits) {
  if (!audits) return [];
  const out = [];
  for (const [id, a] of Object.entries(audits)) {
    if (!a || a.score === null || a.score === undefined || a.score >= 0.9) continue;
    const savingsMs = a.details?.overallSavingsMs;
    const savingsBytes = a.details?.overallSavingsBytes;
    if (!savingsMs && !savingsBytes) continue;
    out.push({
      id,
      title: a.title,
      savingsMs: savingsMs ? Math.round(savingsMs) : null,
      savingsKb: savingsBytes ? Math.round(savingsBytes / 1024) : null
    });
  }
  return out
    .sort((a, b) => (b.savingsMs || 0) - (a.savingsMs || 0) || (b.savingsKb || 0) - (a.savingsKb || 0))
    .slice(0, 6);
}

async function runStrategy(url, strategy, key) {
  const api = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
  api.searchParams.set('url', url);
  api.searchParams.set('strategy', strategy);
  for (const c of ['performance', 'accessibility', 'best-practices', 'seo']) {
    api.searchParams.append('category', c);
  }
  if (key) api.searchParams.set('key', key);

  const res = await fetch(api.href, { signal: AbortSignal.timeout(55_000) });
  const j = await res.json();

  if (j.error) {
    const msg = j.error.message || 'PageSpeed request failed.';
    if (/API key not valid/i.test(msg)) throw new Error('The PageSpeed API key is not valid. Check it is set and restricted to the PageSpeed Insights API.');
    if (/quota|rate/i.test(msg)) throw new Error('PageSpeed quota reached. Try again shortly.');
    if (/Lighthouse returned error|FAILED_DOCUMENT_REQUEST|ERRORED_DOCUMENT/i.test(msg)) {
      throw new Error('Google could not load that page. It may be blocking automated requests.');
    }
    throw new Error(msg);
  }

  const lr = j.lighthouseResult || {};
  const c = lr.categories || {};
  return {
    strategy,
    scores: {
      performance: pct(c.performance?.score),
      accessibility: pct(c.accessibility?.score),
      bestPractices: pct(c['best-practices']?.score),
      seo: pct(c.seo?.score)
    },
    lab: {
      lcp: lr.audits?.['largest-contentful-paint']?.displayValue || null,
      cls: lr.audits?.['cumulative-layout-shift']?.displayValue || null,
      tbt: lr.audits?.['total-blocking-time']?.displayValue || null,
      fcp: lr.audits?.['first-contentful-paint']?.displayValue || null,
      speedIndex: lr.audits?.['speed-index']?.displayValue || null
    },
    field: readVitals(j.loadingExperience),
    originField: readVitals(j.originLoadingExperience),
    opportunities: readOpportunities(lr.audits)
  };
}

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
    || (event.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (rateLimited(ip)) {
    return { statusCode: 429, headers: cors, body: JSON.stringify({ error: 'Too many performance checks. Wait a minute.' }) };
  }

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}
  let target = (body.url || '').trim();
  const mobileOnly = body.mobileOnly !== false;

  if (!target) return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'No address supplied.' }) };
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

  let u;
  try { u = new URL(target); } catch {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'That is not a valid web address.' }) };
  }
  if (!/^https?:$/.test(u.protocol)) {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Only http and https can be checked.' }) };
  }

  const key = process.env.PSI_API_KEY || '';
  if (!key) {
    return {
      statusCode: 200, headers: cors,
      body: JSON.stringify({ error: 'Performance checks are not configured yet. Add PSI_API_KEY in your Netlify environment variables.', notConfigured: true })
    };
  }

  try {
    await assertPublicHost(u.hostname);

    // Mobile first: it is what Google indexes with and what most visitors use.
    const strategies = mobileOnly ? ['mobile'] : ['mobile', 'desktop'];
    const results = await Promise.all(strategies.map(s => runStrategy(u.href, s, key)));

    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({
        url: u.href,
        checkedAt: new Date().toISOString(),
        results: Object.fromEntries(results.map(r => [r.strategy, r]))
      })
    };
  } catch (e) {
    return { statusCode: 200, headers: cors, body: JSON.stringify({ error: e.message || 'The performance check failed.' }) };
  }
};
