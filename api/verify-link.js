const dns = require('dns').promises;
const { parse } = require('tldts');

// --- SSRF & IP Validation ---
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b, c, d] = parts;

  // 0.0.0.0/8
  if (a === 0) return true;
  // 10.0.0.0/8
  if (a === 10) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (Private network)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.0.2.0/24
  if (a === 192 && b === 0 && c === 2) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 (Reserved)
  if (a >= 240) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('::ffff:')) {
    const rest = lower.slice(7);
    if (rest.includes('.')) return isPrivateIPv4(rest);
    const hexParts = rest.split(':');
    if (hexParts.length === 2) {
      const p1 = parseInt(hexParts[0], 16);
      const p2 = parseInt(hexParts[1], 16);
      const v4 = `${(p1 >> 8) & 255}.${p1 & 255}.${(p2 >> 8) & 255}.${p2 & 255}`;
      return isPrivateIPv4(v4);
    }
  }
  if (/^f[cd][0-9a-f]{2}:/i.test(lower)) return true;
  if (/^fe[89ab][0-9a-f]:/i.test(lower)) return true;
  return false;
}

function isPrivateIP(ip) {
  if (ip.includes(':')) return isPrivateIPv6(ip);
  return isPrivateIPv4(ip);
}

async function validateHostSSRF(hostname) {
  const lower = hostname.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.onion')
  ) {
    throw new Error('Access to local/internal hostnames is blocked');
  }

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    if (isPrivateIPv4(hostname)) {
      throw new Error(`Direct connection to private IP ${hostname} is blocked`);
    }
  }

  const addresses = await dns.lookup(hostname, { all: true });
  if (!addresses || addresses.length === 0) {
    throw new Error(`Unable to resolve hostname: ${hostname}`);
  }

  for (const addr of addresses) {
    if (isPrivateIP(addr.address)) {
      throw new Error(`SSRF protection: Hostname resolved to private IP (${addr.address})`);
    }
  }
}

// --- Brand Lookalike Database & Heuristics ---
const BRANDS = {
  tcs: { official: ['tcs.com', 'tcsion.com'], name: 'Tata Consultancy Services (TCS)' },
  infosys: { official: ['infosys.com', 'infy.com'], name: 'Infosys' },
  wipro: { official: ['wipro.com'], name: 'Wipro' },
  accenture: { official: ['accenture.com'], name: 'Accenture' },
  cognizant: { official: ['cognizant.com'], name: 'Cognizant' },
  capgemini: { official: ['capgemini.com'], name: 'Capgemini' },
  hcl: { official: ['hcltech.com', 'hcl.com'], name: 'HCLTech' },
  techmahindra: { official: ['techmahindra.com'], name: 'Tech Mahindra' },
  amazon: { official: ['amazon.com', 'amazon.in', 'amazon.jobs'], name: 'Amazon' },
  google: { official: ['google.com', 'google.co.in', 'google.jobs'], name: 'Google' },
  microsoft: { official: ['microsoft.com', 'microsoft.careers'], name: 'Microsoft' },
  deloitte: { official: ['deloitte.com'], name: 'Deloitte' },
  ey: { official: ['ey.com'], name: 'Ernst & Young (EY)' },
  kpmg: { official: ['kpmg.com'], name: 'KPMG' },
  ibm: { official: ['ibm.com'], name: 'IBM' },
  flipkart: { official: ['flipkart.com', 'flipkartcareers.com'], name: 'Flipkart' },
  linkedin: { official: ['linkedin.com'], name: 'LinkedIn' },
  naukri: { official: ['naukri.com'], name: 'Naukri.com' },
  internshala: { official: ['internshala.com'], name: 'Internshala' },
  indeed: { official: ['indeed.com', 'indeed.co.in'], name: 'Indeed' }
};

const RISKY_TLDS = new Set(['xyz', 'top', 'click', 'work', 'site', 'online', 'shop', 'icu', 'buzz', 'loan', 'tk', 'ml', 'ga', 'cf', 'gq']);
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd', 'ow.ly',
  'shorturl.at', 'tiny.cc', 'rebrand.ly', 't.ly', 's.id', 'v.gd', 'buff.ly',
  'shorte.st', 'adf.ly', 'tinylink.in'
]);
const FREE_BUILDERS = [
  'wixsite.com', 'weebly.com', 'blogspot.com', 'wordpress.com',
  'netlify.app', 'vercel.app', 'github.io', 'sites.google.com',
  'forms.gle', 'docs.google.com', '000webhostapp.com', 'carrd.co', 'webflow.io'
];
const JOB_PLATFORMS = new Set(['linkedin.com', 'internshala.com', 'naukri.com', 'indeed.com', 'unstop.com']);

function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

function checkLookalike(hostname, registrableDomain) {
  if (hostname.includes('xn--')) {
    return {
      matched: true,
      brand: 'Punycode/IDN',
      evidence: `Internationalized/Punycode domain (${hostname}) frequently used in phishing`
    };
  }

  const normalizedHost = hostname
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');

  const regName = registrableDomain ? registrableDomain.toLowerCase() : hostname.toLowerCase();
  const domainPrefix = regName.split('.')[0];

  for (const [key, info] of Object.entries(BRANDS)) {
    if (info.official.includes(regName)) {
      continue;
    }

    if (hostname.includes(key) && !regName.includes(key)) {
      return {
        matched: true,
        brand: info.name,
        evidence: `Brand name "${key}" placed as a subdomain on unrelated domain (${regName})`
      };
    }

    const compoundPatterns = [
      new RegExp(`(?:^|[.-])${key}[-_]?(?:careers|recruitment|jobs|hr|hiring|verify|portal|interview|team|apply|drive)(?:[.-]|$)`, 'i'),
      new RegExp(`(?:^|[.-])(?:careers|recruitment|jobs|hr|hiring|verify|portal|interview|team|apply|drive)[-_]?${key}(?:[.-]|$)`, 'i')
    ];
    for (const pat of compoundPatterns) {
      if (pat.test(regName) || pat.test(hostname)) {
        return {
          matched: true,
          brand: info.name,
          evidence: `Impersonation pattern combining brand name "${key}" with employment keywords (${regName})`
        };
      }
    }

    if (key.length >= 4) {
      const dist = editDistance(domainPrefix, key);
      const threshold = key.length >= 7 ? 2 : 1;
      if (dist > 0 && dist <= threshold) {
        return {
          matched: true,
          brand: info.name,
          evidence: `Typosquatting permutation of brand "${info.name}" (${domainPrefix} vs ${key})`
        };
      }
    }

    if (normalizedHost.includes(key) && !hostname.includes(key)) {
      return {
        matched: true,
        brand: info.name,
        evidence: `Visual lookalike character substitution targeting "${info.name}" (${hostname})`
      };
    }
  }

  return null;
}

// --- RDAP Lookup ---
async function fetchRDAP(domain) {
  if (!domain) return { ageDays: null, eventDate: null, raw: null };
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'application/rdap+json, application/json'
      },
      signal: AbortSignal.timeout(7000)
    });

    if (!res.ok) return { ageDays: null, eventDate: null, raw: null };
    const data = await res.json();
    if (data.events && Array.isArray(data.events)) {
      const regEvent = data.events.find(e => e.eventAction === 'registration' || e.eventAction === 'created');
      if (regEvent && regEvent.eventDate) {
        const regDate = new Date(regEvent.eventDate);
        if (!isNaN(regDate.getTime())) {
          const ageDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
          return { ageDays, eventDate: regEvent.eventDate, raw: data };
        }
      }
    }
    return { ageDays: null, eventDate: null, raw: data };
  } catch (err) {
    return { ageDays: null, eventDate: null, raw: null, error: err.message };
  }
}

// --- Safe Manual Redirect Follower & Fetcher ---
async function fetchPageSafely(startUrl) {
  const redirectChain = [startUrl];
  let currentUrl = startUrl;
  let hops = 0;
  const maxHops = 5;

  try {
    while (hops <= maxHops) {
      const parsedUrl = new URL(currentUrl);
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error(`Unsupported protocol: ${parsedUrl.protocol}`);
      }

      await validateHostSSRF(parsedUrl.hostname);

      const res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache'
        },
        signal: AbortSignal.timeout(7500)
      });

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get('location');
        if (!location) break;
        const nextUrl = new URL(location, currentUrl).toString();
        hops++;
        redirectChain.push(nextUrl);
        currentUrl = nextUrl;
        if (hops > maxHops) break;
        continue;
      }

      const contentType = res.headers.get('content-type') || '';
      const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');

      if (!res.ok || !isHtml) {
        return {
          finalUrl: currentUrl,
          redirectChain,
          readable: false,
          html: '',
          notice: `Page returned HTTP ${res.status} or non-HTML content (${contentType || 'unknown'}). Result is based on domain checks only.`
        };
      }

      const arrayBuffer = await res.arrayBuffer();
      const maxBytes = 1024 * 1024;
      const slice = arrayBuffer.byteLength > maxBytes ? arrayBuffer.slice(0, maxBytes) : arrayBuffer;
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const html = decoder.decode(slice);

      return {
        finalUrl: currentUrl,
        redirectChain,
        readable: true,
        html,
        notice: null
      };
    }

    return {
      finalUrl: currentUrl,
      redirectChain,
      readable: false,
      html: '',
      notice: 'Maximum redirect hops (5) reached. Result is based on domain checks only.'
    };
  } catch (err) {
    return {
      finalUrl: currentUrl,
      redirectChain,
      readable: false,
      html: '',
      notice: `Page content could not be read (${err.message}). Result is based on domain checks only.`
    };
  }
}

// --- HTML Content Analyzer ---
function analyzePageContent(html) {
  const flags = [];
  const cleanHtml = html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, ' ');

  const titleMatch = cleanHtml.match(/<title[^>]*>([^<]+)<\/title>/i);
  const pageTitle = titleMatch ? titleMatch[1].trim() : '';

  const formFieldMatches = cleanHtml.match(/<(?:input|select|textarea)[^>]+(?:name|placeholder|id|aria-label)=["']?([^"'>]+)["']?/gi) || [];
  const formFieldsText = formFieldMatches.join(' ');

  const visibleText = cleanHtml
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();

  const combinedText = `${pageTitle} ${formFieldsText} ${visibleText}`;

  // 1. Money / Fees (HIGH)
  const moneyRules = [
    { re: /\b(?:registration|processing|training|onboarding|verification|joining|documentation|kit|interview|laptop|equipment|security|caution)\s+(?:fee|fees|deposit|deposits|charges?|amount|money)\b/i, label: 'Upfront fee or security deposit demand' },
    { re: /\b(?:100%\s*|fully\s+)?refundable\s+(?:fee|deposit|amount|security|caution)\b/i, label: 'Disguised "refundable" fee demand' },
    { re: /\b(?:send|transfer|pay|deposit)\s+(?:money|amount|funds|fee)\s+(?:via|to|using)\s+(?:upi|gpay|phonepe|paytm|qr\s*code|bank\s*transfer)\b/i, label: 'Direct payment request via UPI / wallet' },
    { re: /\b[\w.\-]{2,}@(?:upi|ybl|okaxis|okhdfcbank|oksbi|okicici|paytm|ibl|axl|apl)\b/i, label: 'Personal UPI ID published for job application' },
    { re: /\b(?:razorpay\.me|cashfree\.com\/pay|instamojo\.com|p-y\.tm)\/\S+/i, label: 'Payment gateway link embedded in job post' }
  ];

  for (const rule of moneyRules) {
    const m = combinedText.match(rule.re);
    if (m) {
      flags.push({
        id: 'content_fee_demand',
        severity: 'high',
        label: rule.label,
        evidence: m[0].slice(0, 100)
      });
      break;
    }
  }

  // 2. Sensitive Data Collection (HIGH)
  const sensitiveRules = [
    { re: /\b(?:aadhaar|aadhar)(?:\s*(?:card|no\.?|number))?\b/i, label: 'Aadhaar collection on job application form' },
    { re: /\b(?:pan\s*card|pan\s*number)\b/i, label: 'PAN card collection on unverified form' },
    { re: /\b(?:bank\s*account\s*(?:no\.?|number)|ifsc(?:\s*code)?|net\s*banking\s*password)\b/i, label: 'Banking details or password requested' },
    { re: /\b(?:otp|one[- ]time[- ]password|pin\s*number)\b/i, label: 'OTP or security PIN requested' },
    { re: /\b(?:passport\s*(?:no\.?|number))\b/i, label: 'Passport number requested on job application' }
  ];

  for (const rule of sensitiveRules) {
    const m = combinedText.match(rule.re);
    if (m) {
      flags.push({
        id: 'content_sensitive_data',
        severity: 'high',
        label: rule.label,
        evidence: m[0].slice(0, 100)
      });
      break;
    }
  }

  // 3. Messaging only or free-mail contact (MEDIUM)
  const hasTelegram = /\b(?:t\.me|telegram\.me|telegram)\b/i.test(combinedText);
  const hasWhatsApp = /\b(?:wa\.me|api\.whatsapp\.com|whatsapp)\b/i.test(combinedText);
  const freeMailMatch = combinedText.match(/\b[A-Za-z0-9._%+-]+@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|rediffmail\.com)\b/i);
  const corporateMailMatch = combinedText.match(/\b[A-Za-z0-9._%+-]+@(?!(?:gmail|yahoo|outlook|hotmail|rediffmail)\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i);

  if ((hasTelegram || hasWhatsApp) && !corporateMailMatch) {
    const contactEvidence = hasTelegram && hasWhatsApp ? 'WhatsApp & Telegram' : hasTelegram ? 'Telegram' : 'WhatsApp';
    flags.push({
      id: 'content_chat_only_contact',
      severity: 'medium',
      label: 'Recruitment routed solely through messaging app',
      evidence: `Direct chat handoff via ${contactEvidence} without corporate email`
    });
  } else if (freeMailMatch && !corporateMailMatch) {
    flags.push({
      id: 'content_freemail_contact',
      severity: 'medium',
      label: 'Free public email used for official hiring',
      evidence: freeMailMatch[0]
    });
  }

  // 4. Pressure & Guarantees (MEDIUM)
  const pressureRules = [
    { re: /\b(?:guaranteed|100%|assured)\s+(?:job|selection|placement|hiring|joining)\b/i, label: 'Guaranteed placement promise' },
    { re: /\b(?:no|without)\s+(?:interview|test|exam|assessment)\b|\bdirect\s+(?:selection|joining)\b/i, label: 'Selection without interview' },
    { re: /\b(?:limited\s+(?:seats?|slots?|positions?|openings?)|only\s+\d+\s+seats?\s+left)\b/i, label: 'Artificial scarcity pressure' },
    { re: /\b(?:apply\s+within\s+(?:24|12|48)\s*(?:hours?|hrs?)|offer\s+expires\s+today|immediate\s+joining)\b/i, label: 'Urgent deadline pressure' }
  ];

  for (const rule of pressureRules) {
    const m = combinedText.match(rule.re);
    if (m) {
      flags.push({
        id: 'content_pressure_tactics',
        severity: 'medium',
        label: rule.label,
        evidence: m[0].slice(0, 100)
      });
      break;
    }
  }

  // 5. Unrealistic pay (MEDIUM)
  const payMatch = combinedText.match(/\b(?:stipend|salary|pay|income|earning)\s*(?:of|is|:|-)?\s*(?:₹|rs\.?|inr)\s*(?:5[0-9],[0-9]{3}|[6-9][0-9],[0-9]{3}|1[0-9]{2},[0-9]{3}|[2-9][0-9]{5})\s*(?:\/|\s*per\s*)(?:month|mo|week|day)\b/i) ||
                   combinedText.match(/\b(?:earn|get)\s+(?:₹|rs\.?|inr)\s*(?:[1-9][0-9]{3,5})\s*(?:daily|per\s+day|every\s+day)\b/i);
  if (payMatch) {
    flags.push({
      id: 'content_unrealistic_pay',
      severity: 'medium',
      label: 'Disproportionately high pay for entry-level / intern role',
      evidence: payMatch[0]
    });
  }

  // 6. Missing Company Identity (MEDIUM)
  const hasAddress = /\b(?:address|registered\s+office|headquarters|location|suite|floor|road|street|nagar|sector|pin\s*code)\b/i.test(combinedText);
  const hasAboutOrContact = /\b(?:about\s+us|contact\s+us|privacy\s+policy|terms\s+of\s+service)\b/i.test(cleanHtml);
  if (!hasAddress && !hasAboutOrContact && visibleText.length < 800) {
    flags.push({
      id: 'content_missing_identity',
      severity: 'medium',
      label: 'Sparse page lacking corporate identity and physical address',
      evidence: 'No physical address, contact page, or corporate registration details found'
    });
  }

  return flags;
}

// --- Core Link Verification Function ---
async function verifyLink(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw { status: 400, message: 'Missing "url" parameter.' };
  }

  let formattedUrl = rawUrl.trim();
  if (!/^https?:\/\//i.test(formattedUrl)) {
    formattedUrl = 'https://' + formattedUrl;
  }

  if (formattedUrl.length > 2048) {
    throw { status: 400, message: 'URL exceeds maximum allowed length of 2048 characters.' };
  }

  let initialParsed;
  try {
    initialParsed = new URL(formattedUrl);
  } catch (e) {
    throw { status: 400, message: 'Invalid URL format.' };
  }

  if (initialParsed.protocol !== 'http:' && initialParsed.protocol !== 'https:') {
    throw { status: 400, message: 'Only HTTP and HTTPS URLs are permitted.' };
  }

  const initialHostname = initialParsed.hostname.toLowerCase();
  const initialParsedDomain = parse(initialHostname);
  const initialRegistrable = initialParsedDomain.domain || initialHostname;

  const [rdapResult, pageResult] = await Promise.all([
    fetchRDAP(initialRegistrable),
    fetchPageSafely(formattedUrl)
  ]);

  const finalUrl = pageResult.finalUrl || formattedUrl;
  const redirectChain = pageResult.redirectChain || [formattedUrl];
  let finalParsed;
  try {
    finalParsed = new URL(finalUrl);
  } catch (e) {
    finalParsed = initialParsed;
  }

  const finalHostname = finalParsed.hostname.toLowerCase();
  const finalParsedDomain = parse(finalHostname);
  const finalRegistrable = finalParsedDomain.domain || finalHostname;
  const finalTld = finalParsedDomain.publicSuffix || finalHostname.split('.').pop();
  const isHttps = finalParsed.protocol === 'https:';

  const flags = [];
  const positives = [];

  // 1. Domain Age
  const domainAgeDays = rdapResult.ageDays;
  if (domainAgeDays !== null && domainAgeDays !== undefined) {
    if (domainAgeDays < 30) {
      flags.push({
        id: 'domain_age_critical',
        severity: 'high',
        label: 'Extremely new domain (< 30 days)',
        evidence: `Domain registered only ${domainAgeDays} days ago (${rdapResult.eventDate ? rdapResult.eventDate.slice(0, 10) : 'recent'})`
      });
    } else if (domainAgeDays < 180) {
      flags.push({
        id: 'domain_age_recent',
        severity: 'medium',
        label: 'Recently registered domain (< 6 months)',
        evidence: `Domain registered ${domainAgeDays} days ago (${rdapResult.eventDate ? rdapResult.eventDate.slice(0, 10) : 'recent'})`
      });
    } else if (domainAgeDays >= 730) {
      positives.push(`Established domain: registered ${Math.floor(domainAgeDays / 365)} years ago (${rdapResult.eventDate ? rdapResult.eventDate.slice(0, 10) : ''})`);
    }
  } else {
    flags.push({
      id: 'domain_age_unknown',
      severity: 'info',
      label: 'Domain age unknown',
      evidence: 'RDAP registration record unavailable or lookup unresolvable'
    });
  }

  // 2. HTTPS Check
  if (!isHttps) {
    flags.push({
      id: 'insecure_http',
      severity: 'medium',
      label: 'Unencrypted connection (Plain HTTP)',
      evidence: finalUrl
    });
  }

  // 3. Lookalike Detection
  const lookalikeInitial = checkLookalike(initialHostname, initialRegistrable);
  const lookalikeFinal = checkLookalike(finalHostname, finalRegistrable);
  const lookalikeMatch = lookalikeInitial || lookalikeFinal;
  if (lookalikeMatch) {
    flags.push({
      id: 'brand_lookalike',
      severity: 'high',
      label: `Lookalike domain imitating ${lookalikeMatch.brand}`,
      evidence: lookalikeMatch.evidence
    });
  }

  // 4. Risky TLDs
  if (RISKY_TLDS.has(finalTld) || (initialParsedDomain.publicSuffix && RISKY_TLDS.has(initialParsedDomain.publicSuffix))) {
    flags.push({
      id: 'risky_tld',
      severity: 'medium',
      label: 'High-risk / low-cost TLD frequently abused in recruitment scams',
      evidence: `.${finalTld}`
    });
  }

  // 5. Shorteners
  if (SHORTENERS.has(initialHostname) || redirectChain.some(u => {
    try { return SHORTENERS.has(new URL(u).hostname.toLowerCase()); } catch (_) { return false; }
  })) {
    flags.push({
      id: 'url_shortener',
      severity: 'medium',
      label: 'URL shortener used to conceal true destination',
      evidence: initialHostname
    });
  }

  // 6. Free Builders
  const matchedBuilder = FREE_BUILDERS.find(b => finalHostname.includes(b) || initialHostname.includes(b));
  if (matchedBuilder) {
    flags.push({
      id: 'free_builder_host',
      severity: 'medium',
      label: 'Company site hosted on free website builder / generic form',
      evidence: `${finalHostname} (${matchedBuilder})`
    });
  }

  // 7. Cross-domain Redirect
  if (initialRegistrable && finalRegistrable && initialRegistrable !== finalRegistrable) {
    flags.push({
      id: 'cross_domain_redirect',
      severity: 'medium',
      label: 'Redirected to a completely different domain',
      evidence: `${initialRegistrable} → ${finalRegistrable}`
    });
  }

  // 8. Known Platforms
  if (JOB_PLATFORMS.has(finalRegistrable)) {
    flags.push({
      id: 'job_platform_notice',
      severity: 'info',
      label: 'Known job platform (posting may still be unvetted)',
      evidence: finalRegistrable
    });
  }

  // 9. Page Content Flags
  let notice = pageResult.notice || null;
  if (pageResult.readable && pageResult.html) {
    const contentFlags = analyzePageContent(pageResult.html);
    flags.push(...contentFlags);
  } else if (!notice) {
    notice = 'Page content could not be read. Result is based on domain checks only.';
  }

  return {
    finalUrl,
    redirectChain,
    domain: finalRegistrable,
    domainAgeDays,
    https: isHttps,
    readable: pageResult.readable,
    flags,
    positives,
    notice
  };
}

// --- Vercel Serverless Function Handler (Node.js API Route) ---
module.exports = async function handler(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed. Send POST { "url": "..." }' });
  }

  try {
    let body = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (_) {
        return res.status(400).json({ error: 'Invalid JSON payload. Expected { "url": "..." }' });
      }
    }
    body = body || {};

    const result = await verifyLink(body.url);
    return res.status(200).json(result);
  } catch (err) {
    const status = err.status || 500;
    const errorMsg = err.message || 'An error occurred during link verification';
    return res.status(status).json({ error: errorMsg });
  }
};

// Also export verifyLink for local test runners
module.exports.verifyLink = verifyLink;
