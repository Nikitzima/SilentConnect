const BASE_DOMAIN = process.env.BASE_DOMAIN || ['silent', 'connect', '.net'].join('');

const UPSTREAM_NODES = [
  { name: 'NL', origin: process.env.ORIGIN_NL || `https://edge.${BASE_DOMAIN}`, host: process.env.HOST_NL || `edge.${BASE_DOMAIN}` },
  { name: 'PL', origin: process.env.ORIGIN_PL || `https://pl.${BASE_DOMAIN}`, host: process.env.HOST_PL || `pl.${BASE_DOMAIN}` },
  { name: 'FI', origin: process.env.ORIGIN_FI || `https://fi.${BASE_DOMAIN}`, host: process.env.HOST_FI || `fi.${BASE_DOMAIN}` },
];

const TIMEOUT_MS = 3500;
const MICROCACHE_TTL_MS = 5000;

// In-memory microcache
const microCache = new Map();

function getCached(key) {
  const item = microCache.get(key);
  if (!item) return null;
  if (Date.now() - item.ts > MICROCACHE_TTL_MS) {
    microCache.delete(key);
    return null;
  }
  return item;
}

function setCache(key, status, headers, body, isB64) {
  microCache.set(key, { status, headers, body, isB64, ts: Date.now() });
  if (microCache.size > 2000) {
    const oldestKey = microCache.keys().next().value;
    microCache.delete(oldestKey);
  }
}

export async function handler(event, context) {
  const httpMethod = (event.httpMethod || 'GET').toUpperCase();
  let fullPath = event.url || event.path || '/';
  if (!fullPath.includes('?')) {
    const queryParams = event.queryStringParameters || {};
    const queryParts = [];
    for (const [k, v] of Object.entries(queryParams)) {
      queryParts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    if (queryParts.length > 0) {
      fullPath += `?${queryParts.join('&')}`;
    }
  }

  const incomingHost = (
    event.headers?.['host'] ||
    event.headers?.['Host'] ||
    event.headers?.['x-forwarded-host'] ||
    ''
  ).toLowerCase().split(':')[0].trim();

  const clientIp =
    event.headers?.['x-forwarded-for']?.split(',')[0].trim() ||
    event.headers?.['x-real-ip'] ||
    '127.0.0.1';

  const isCacheable =
    httpMethod === 'GET' &&
    !fullPath.startsWith('/order') &&
    !fullPath.startsWith('/api/') &&
    !fullPath.startsWith('/cabinet') &&
    !fullPath.startsWith('/auth') &&
    !fullPath.includes('/renew');

  const cacheKey = `${incomingHost}:${httpMethod}:${fullPath}`;

  // 1. Microcache check for GET
  if (isCacheable) {
    const cached = getCached(cacheKey);
    if (cached) {
      return {
        statusCode: cached.status,
        headers: {
          ...cached.headers,
          'X-Edge-Cache': 'HIT',
          'X-Edge-Proxy': 'SilentConnect-YC',
        },
        body: cached.body,
        isBase64Encoded: Boolean(cached.isB64),
      };
    }
  }

  // Request Body
  let reqBody = undefined;
  if (httpMethod !== 'GET' && httpMethod !== 'HEAD' && event.body) {
    reqBody = event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body;
  }

  // 2. Failover: NL -> PL -> FI
  for (const node of UPSTREAM_NODES) {
    try {
      const targetUrl = `${node.origin}${fullPath}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const fwdHeaders = new Headers();
      for (const [key, value] of Object.entries(event.headers || {})) {
        const lk = key.toLowerCase();
        if (
          lk !== 'host' &&
          lk !== 'content-length' &&
          lk !== 'accept-encoding' &&
          !lk.startsWith('x-yc') &&
          !lk.startsWith('x-serverless')
        ) {
          fwdHeaders.set(key, value);
        }
      }
      const targetHost = incomingHost.includes(BASE_DOMAIN) ? incomingHost : node.host;
      fwdHeaders.set('Host', targetHost);
      fwdHeaders.set('X-Forwarded-Host', incomingHost || targetHost);
      fwdHeaders.set('X-Forwarded-For', clientIp);
      fwdHeaders.set('X-Forwarded-Proto', 'https');
      fwdHeaders.set('X-Edge-Proxy', 'SilentConnect-YC-Failover');

      const upstreamResp = await fetch(targetUrl, {
        method: httpMethod,
        headers: fwdHeaders,
        body: reqBody,
        signal: controller.signal,
        redirect: 'manual',
      });
      clearTimeout(timeoutId);

      if (upstreamResp.status >= 502 && upstreamResp.status <= 504) {
        continue;
      }

      const arrayBuf = await upstreamResp.arrayBuffer();
      const bodyBuffer = Buffer.from(arrayBuf);

      const outHeaders = {};
      for (const [k, v] of upstreamResp.headers.entries()) {
        const lk = k.toLowerCase();
        if (lk !== 'content-encoding' && lk !== 'transfer-encoding' && lk !== 'content-length') {
          outHeaders[k] = v;
        }
      }
      outHeaders['X-Edge-Node'] = node.name;
      outHeaders['X-Edge-Proxy'] = 'SilentConnect-YC';
      outHeaders['X-Edge-Cache'] = 'MISS';

      const contentType = (upstreamResp.headers.get('content-type') || '').toLowerCase();
      const isText = contentType.includes('text') || contentType.includes('json') || contentType.includes('javascript') || contentType.includes('xml');

      const respPayload = isText ? bodyBuffer.toString('utf-8') : bodyBuffer.toString('base64');
      const isB64 = !isText;

      if (isCacheable && upstreamResp.status === 200) {
        setCache(cacheKey, upstreamResp.status, outHeaders, respPayload, isB64);
      }

      return {
        statusCode: upstreamResp.status,
        headers: outHeaders,
        body: respPayload,
        isBase64Encoded: isB64,
      };
    } catch (err) {
      continue;
    }
  }

  // 3. Emergency Fallbacks
  const ua = (event.headers?.['user-agent'] || '').toLowerCase();
  const lowerPath = (fullPath || '').toLowerCase();

  if (lowerPath.includes('/singbox')) {
    const emergencySingbox = {
      outbounds: [
        { type: 'block', tag: '🛑 Серверы на плановом обновлении (не удаляйте профиль)' },
        { type: 'block', tag: '⏳ Нажмите «Обновить» через 15-30 минут' },
        { type: 'block', tag: '💬 Чат поддержки: @SilentConnectSupport' },
      ],
    };
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Edge-Emergency': 'true',
      },
      body: Buffer.from(JSON.stringify(emergencySingbox, null, 2)).toString('base64'),
      isBase64Encoded: true,
    };
  }

  if (lowerPath.includes('/json') || ua.includes('happ') || ua.includes('v2ray') || ua.includes('box')) {
    const emergencyHapp = [
      {
        remarks: '🛑 1. Серверы на плановом обновлении',
        protocol: 'blackhole',
        settings: {},
        tag: 'proxy-stub-1',
        outbounds: [{ protocol: 'blackhole', tag: 'proxy', settings: {} }],
        meta: {
          'sub-info-color': 'yellow',
          'sub-info-text': '⚠️ Идет обновление серверных узлов. Не удаляйте профиль — он обновится автоматически!',
          'sub-info-button-text': 'Поддержка',
          'sub-info-button-link': 'https://t.me/SilentConnectSupport',
        },
      },
      {
        remarks: '🔄 2. Инженеры настраивают резервные адреса',
        protocol: 'blackhole',
        settings: {},
        tag: 'proxy-stub-2',
        outbounds: [{ protocol: 'blackhole', tag: 'proxy-2', settings: {} }],
      },
      {
        remarks: '⏳ 3. Нажмите «Обновить» через 15–30 минут',
        protocol: 'blackhole',
        settings: {},
        tag: 'proxy-stub-3',
        outbounds: [{ protocol: 'blackhole', tag: 'proxy-3', settings: {} }],
      },
      {
        remarks: '💬 4. Чат поддержки: @SilentConnectSupport',
        protocol: 'blackhole',
        settings: {},
        tag: 'proxy-stub-4',
        outbounds: [{ protocol: 'blackhole', tag: 'proxy-4', settings: {} }],
      },
    ];
    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Edge-Emergency': 'true',
      },
      body: Buffer.from(JSON.stringify(emergencyHapp, null, 2)).toString('base64'),
      isBase64Encoded: true,
    };
  }

  const emergencyHtml = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>SilentConnect — Обновление узлов</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: #131b2e; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 36px 28px; max-width: 460px; width: 100%; text-align: center; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
    h1 { font-size: 20px; font-weight: 700; margin: 0 0 14px 0; color: #38bdf8; }
    p { font-size: 14px; color: #94a3b8; line-height: 1.6; margin: 0 0 24px 0; }
    .badge { display: inline-block; padding: 6px 14px; background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.25); color: #fbbf24; border-radius: 20px; font-size: 12.5px; font-weight: 600; margin-bottom: 18px; }
    .btn { display: inline-block; background: #0284c7; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 10px; font-size: 14px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">⚙️ Технические работы</div>
    <h1>Обновление серверных узлов</h1>
    <p>Ведутся плановые работы по замене и перенастройке серверов. Пожалуйста, не удаляйте подписку в приложении — она автоматически обновится сразу после окончания работ.</p>
    <a href="https://t.me/SilentConnectSupport" class="btn">💬 Чат поддержки в Telegram</a>
  </div>
</body>
</html>`;

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Edge-Emergency': 'true',
    },
    body: Buffer.from(emergencyHtml).toString('base64'),
    isBase64Encoded: true,
  };
}
