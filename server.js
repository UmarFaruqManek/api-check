const express = require('express');
const cors = require('cors');
const path = require('path');
const whois = require('whois-json');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory cache untuk mencegah rate limit
// Key: domain, Value: { data, timestamp }
const cache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 Jam TTL

/**
 * Normalisasi nama domain dari input user
 */
function cleanDomainInput(input) {
  if (!input) return '';
  let domain = input.trim().toLowerCase();
  // Hilangkan protokol (http://, https://) dan www
  domain = domain.replace(/^https?:\/\//, '');
  domain = domain.replace(/^www\./, '');
  // Hilangkan path atau query jika ada
  domain = domain.split('/')[0];
  domain = domain.split('?')[0];
  domain = domain.split(':')[0];
  return domain;
}

/**
 * Query RDAP (Registration Data Access Protocol)
 * Standar resmi ICANN penerus WHOIS berbasis REST JSON
 */
async function queryRdap(domain) {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/rdap+json, application/json',
      'User-Agent': 'DomainWhoisApi/1.0 (Node.js)'
    },
    signal: AbortSignal.timeout(8000)
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Domain '${domain}' tidak ditemukan (Not Found / Available).`);
    }
    throw new Error(`Server RDAP merespon status ${response.status}`);
  }

  const data = await response.json();

  const getEvent = (action) => data.events?.find(e => e.eventAction === action)?.eventDate || null;
  const registrarEntity = data.entities?.find(e => e.roles?.includes('registrar'));
  const registrarName = registrarEntity?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] 
    || registrarEntity?.handle 
    || 'Unknown';

  const nameServers = (data.nameservers || []).map(ns => ns.ldhName || ns.handle).filter(Boolean);

  return {
    domainName: data.ldhName || domain.toUpperCase(),
    registryDomainId: data.handle || null,
    registrar: registrarName,
    creationDate: getEvent('registration'),
    expirationDate: getEvent('expiration'),
    updatedDate: getEvent('last changed'),
    status: data.status || [],
    nameServers: nameServers,
    rawRdap: data
  };
}

/**
 * Fallback: Query WHOIS Port 43 via whois-json
 */
async function queryWhoisPort43(domain) {
  const raw = await whois(domain, { follow: 3, timeout: 8000 });
  
  // Deteksi pesan notice atau limit
  const keys = Object.keys(raw);
  const isRetiredOrLimited = keys.some(k => 
    k.toLowerCase().includes('retired') || 
    k.toLowerCase().includes('ratelimit') || 
    k.toLowerCase().includes('limit')
  );

  if (isRetiredOrLimited) {
    throw new Error('Server WHOIS Port 43 membatasi query (Rate Limit / Migrated to RDAP).');
  }

  return {
    domainName: raw.domainName || domain.toUpperCase(),
    registryDomainId: raw.registryDomainId || null,
    registrar: raw.registrar || raw.registrarName || 'Unknown',
    creationDate: raw.creationDate || raw.creationDateTimestamp || null,
    expirationDate: raw.registryExpiryDate || raw.registrarRegistrationExpirationDate || null,
    updatedDate: raw.updatedDate || null,
    status: raw.domainStatus ? (Array.isArray(raw.domainStatus) ? raw.domainStatus : [raw.domainStatus]) : [],
    nameServers: raw.nameServer ? (Array.isArray(raw.nameServer) ? raw.nameServer : [raw.nameServer]) : [],
    rawWhois: raw
  };
}

/**
 * Endpoint Utama API WHOIS
 * GET /api/whois?domain=dicoding.com
 */
app.get('/api/whois', async (req, res) => {
  const startTime = Date.now();
  const rawInput = req.query.domain;

  if (!rawInput) {
    return res.status(400).json({
      status: 'error',
      message: 'Parameter "?domain=" wajib diisi. Contoh: /api/whois?domain=dicoding.com'
    });
  }

  const domain = cleanDomainInput(rawInput);

  if (!domain || !domain.includes('.')) {
    return res.status(400).json({
      status: 'error',
      message: 'Format domain tidak valid. Pastikan menyertakan ekstensi (TLD), misalnya: dicoding.com'
    });
  }

  // 1. Cek Cache Memory
  if (cache.has(domain)) {
    const cachedEntry = cache.get(domain);
    if (Date.now() - cachedEntry.timestamp < CACHE_TTL_MS) {
      return res.json({
        status: 'success',
        domain: domain,
        source: 'cache',
        executionTimeMs: Date.now() - startTime,
        data: cachedEntry.data
      });
    } else {
      cache.delete(domain); // Cache expired
    }
  }

  // 2. Coba via RDAP terlebih dahulu (Standar Modern ICANN, tidak terkena blokir Port 43 Verisign)
  try {
    const result = await queryRdap(domain);
    
    // Simpan ke Cache
    cache.set(domain, {
      timestamp: Date.now(),
      data: result
    });

    return res.json({
      status: 'success',
      domain: domain,
      source: 'rdap',
      executionTimeMs: Date.now() - startTime,
      data: result
    });

  } catch (rdapError) {
    console.warn(`[RDAP Warning] ${domain}: ${rdapError.message}. Mencoba fallback ke WHOIS Port 43...`);

    // 3. Fallback ke WHOIS Socket Port 43
    try {
      const whoisResult = await queryWhoisPort43(domain);

      cache.set(domain, {
        timestamp: Date.now(),
        data: whoisResult
      });

      return res.json({
        status: 'success',
        domain: domain,
        source: 'whois-port43',
        executionTimeMs: Date.now() - startTime,
        data: whoisResult
      });

    } catch (whoisError) {
      return res.status(502).json({
        status: 'error',
        domain: domain,
        message: 'Gagal mendapatkan data domain dari server WHOIS/RDAP.',
        errors: {
          rdap: rdapError.message,
          whois: whoisError.message
        }
      });
    }
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    cachedDomainsCount: cache.size,
    timestamp: new Date().toISOString()
  });
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 WHOIS API Server aktif di: http://localhost:${PORT}`);
  console.log(`📡 Endpoint API: http://localhost:${PORT}/api/whois?domain=dicoding.com`);
  console.log(`🖥️  Testing UI:  http://localhost:${PORT}`);
  console.log(`=================================================`);
  });
}
