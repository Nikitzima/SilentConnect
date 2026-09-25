export const config = {
  runtime: 'edge',
};

const BASE_DOMAIN = process.env.BASE_DOMAIN || ['silent', 'connect', '.net'].join('');

const UPSTREAM_NODES = [
  { name: 'NL', origin: process.env.ORIGIN_NL || `https://edge.${BASE_DOMAIN}`, host: process.env.HOST_NL || `edge.${BASE_DOMAIN}` },
  { name: 'PL', origin: process.env.ORIGIN_PL || `https://pl.${BASE_DOMAIN}`, host: process.env.HOST_PL || `pl.${BASE_DOMAIN}` },
  { name: 'FI', origin: process.env.ORIGIN_FI || `https://fi.${BASE_DOMAIN}`, host: process.env.HOST_FI || `fi.${BASE_DOMAIN}` },
];

const TIMEOUT_MS = 2500;
const MAX_RPS = 3;
const MICROCACHE_TTL_MS = 5000;

// In-memory rate limiter per IP (sliding 1-second window)
const rateMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let window = rateMap.get(ip) || [];
  window = window.filter((t) => now - t < 1000);
  if (window.length >= MAX_RPS) {
    return false;
  }
  window.push(now);
  rateMap.set(ip, window);
  if (rateMap.size > 5000) {
    const oldestKey = rateMap.keys().next().value;
    rateMap.delete(oldestKey);
  }
  return true;
}

// In-memory microcache for rapid click spam protection
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

function setCache(key, status, headers, body) {
  microCache.set(key, { status, headers, body, ts: Date.now() });
  if (microCache.size > 2000) {
    const oldestKey = microCache.keys().next().value;
    microCache.delete(oldestKey);
  }
}

export default async function handler(request) {
  const url = new URL(request.url);
  const clientIp =
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    request.headers.get('x-real-ip') ||
    '127.0.0.1';

  // 1. Strict Rate Limiting (max 3 RPS per IP)
  if (!checkRateLimit(clientIp)) {
    return new Response(
      JSON.stringify({
        error: 'too_many_requests',
        message: 'Лимит: не более 3 запросов в секунду. Пожалуйста, подождите.',
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Retry-After': '2',
        },
      }
    );
  }

  const cacheKey = `${request.method}:${url.pathname}${url.search}`;

  // 2. Microcache check for GET
  if (request.method === 'GET') {
    const cached = getCached(cacheKey);
    if (cached) {
      const respHeaders = new Headers(cached.headers);
      respHeaders.set('X-Edge-Cache', 'HIT');
      return new Response(cached.body, {
        status: cached.status,
        headers: respHeaders,
      });
    }
  }

  // Read request body if present (for POST/PUT)
  let reqBody = null;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      reqBody = await request.arrayBuffer();
    } catch (_) {}
  }

  // 3. Try Upstreams in order: PL -> NL -> FI
  for (const node of UPSTREAM_NODES) {
    try {
      const targetUrl = `${node.origin}${url.pathname}${url.search}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const fwdHeaders = new Headers();
      for (const [key, value] of request.headers.entries()) {
        const lk = key.toLowerCase();
        if (
          lk !== 'host' &&
          lk !== 'content-length' &&
          !lk.startsWith('x-vercel')
        ) {
          fwdHeaders.set(key, value);
        }
      }
      fwdHeaders.set('Host', node.host);
      fwdHeaders.set('X-Forwarded-For', clientIp);
      fwdHeaders.set('X-Edge-Proxy', 'SilentConnect-Failover');

      const upstreamResp = await fetch(targetUrl, {
        method: request.method,
        headers: fwdHeaders,
        body: reqBody,
        signal: controller.signal,
        redirect: 'manual',
      });
      clearTimeout(timeoutId);

      if (upstreamResp.status >= 502 && upstreamResp.status <= 504) {
        continue;
      }

      const respBody = await upstreamResp.arrayBuffer();
      const outHeaders = new Headers();

      for (const [k, v] of upstreamResp.headers.entries()) {
        const lk = k.toLowerCase();
        if (lk !== 'content-encoding' && lk !== 'transfer-encoding') {
          outHeaders.set(k, v);
        }
      }
      outHeaders.set('X-Edge-Node', node.name);
      outHeaders.set('X-Edge-Cache', 'MISS');

      if (request.method === 'GET' && upstreamResp.status === 200) {
        setCache(cacheKey, upstreamResp.status, Object.fromEntries(outHeaders.entries()), respBody);
      }

      return new Response(respBody, {
        status: upstreamResp.status,
        headers: outHeaders,
      });
    } catch (err) {
      continue;
    }
  }

  // 4. Emergency Fallback when ALL nodes are down
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const path = url.pathname.toLowerCase();

  // Emergency Sing-box response
  if (path.includes('/singbox')) {
    const emergencySingbox = {
      outbounds: [
        {
          type: 'block',
          tag: '🛑 Серверы на плановом обновлении (не удаляйте профиль)',
        },
        {
          type: 'block',
          tag: '⏳ Нажмите «Обновить» через 15-30 минут',
        },
        {
          type: 'block',
          tag: '💬 Чат поддержки: @SilentConnectSupport',
        },
      ],
    };
    return new Response(JSON.stringify(emergencySingbox, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Edge-Emergency': 'true',
      },
    });
  }

  // Emergency JSON / Happ response
  if (path.includes('/json') || ua.includes('happ') || ua.includes('v2ray') || ua.includes('box')) {
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

    return new Response(JSON.stringify(emergencyHapp, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Edge-Emergency': 'true',
      },
    });
  }

  // Emergency HTML Page for Browser
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
    .btn { display: inline-block; background: #0284c7; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 10px; font-size: 14px; font-weight: 600; transition: background 0.2s; }
    .btn:hover { background: #0369a1; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">⚙️ Технические работы</div>
    <h1>Обновление серверных узлов</h1>
    <p>Ведутся плановые работы по замене и перенастройке серверов SilentConnect. Пожалуйста, не удаляйте подписку в приложении — она автоматически обновится сразу после окончания работ.</p>
    <a href="https://t.me/SilentConnectSupport" class="btn">💬 Чат поддержки в Telegram</a>
  </div>
</body>
</html>`;

  return new Response(emergencyHtml, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'X-Edge-Emergency': 'true',
    },
  });
}
