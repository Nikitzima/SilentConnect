import { fetch } from 'sdk/fetch';
import { SETTINGS } from './config.js';
import { sha256Hex, hmacSha256Hex, constantTimeEquals, nowTs } from './security.js';

export class DigisellerClient {
  constructor(settings = SETTINGS) {
    this.sellerId = String(settings.digisellerSellerId || '').trim();
    this.apiKey = String(settings.digisellerApiKey || '').trim();
    this.secretKey = String(settings.digisellerSecretKey || '').trim();
    this.baseUrl = 'https://api.digiseller.com';
    this._token = null;
    this._tokenExpiresAt = 0;
  }

  async getToken(forceRefresh = false) {
    const now = nowTs();
    if (!forceRefresh && this._token && now < this._tokenExpiresAt) {
      return this._token;
    }
    if (!this.sellerId || !this.apiKey) {
      throw new Error('Digiseller sellerId and apiKey must be configured');
    }
    const sign = sha256Hex(`${this.apiKey}${now}`);
    const res = await fetch(`${this.baseUrl}/api/apilogin`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: typeof fetch.body?.json === 'function'
        ? fetch.body.json({
            seller_id: Number(this.sellerId),
            timestamp: now,
            sign,
          })
        : JSON.stringify({
            seller_id: Number(this.sellerId),
            timestamp: now,
            sign,
          }),
    });
    const data = await res.json();
    if (data.retval !== 0 || !data.token) {
      throw new Error(`Digiseller apilogin failed: ${data.desc || data.retdesc || data.retval}`);
    }
    this._token = String(data.token);
    this._tokenExpiresAt = now + 110 * 60;
    return this._token;
  }

  async request(endpoint, method = 'GET', data = null) {
    const token = await this.getToken();
    const sep = endpoint.includes('?') ? '&' : '?';
    const url = `${this.baseUrl}${endpoint}${sep}token=${encodeURIComponent(token)}`;
    const options = {
      method,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    };
    if (data !== null) {
      options.body =
        typeof fetch.body?.json === 'function' ? fetch.body.json(data) : JSON.stringify(data);
    }
    const res = await fetch(url, options);
    const text = await res.text();
    return text ? JSON.parse(text) : {};
  }

  verifyWebhookSignature(payload = {}) {
    const secret = (this.secretKey || this.apiKey).trim();
    if (!secret) return false;
    const incoming = String(
      payload.sign || payload.signature || payload.Sign || payload.SHA256 || payload.sha256 || ''
    )
      .trim()
      .toLowerCase();
    if (!incoming) return false;

    const idGoods = String(payload.id_goods || payload.product_id || payload.id_d || '').trim();
    const idInvoice = String(payload.id_invoice || payload.invoice_id || payload.id_i || '').trim();
    const datePay = String(payload.date_pay || payload.date || '').trim();
    const amount = String(payload.amount || payload.pay_amount || '').trim();

    const c0 = sha256Hex(`${secret.toLowerCase()};${idInvoice};${idGoods}`).toLowerCase();
    if (constantTimeEquals(c0, incoming)) return true;

    const c0b = sha256Hex(`${secret};${idInvoice};${idGoods}`).toLowerCase();
    if (constantTimeEquals(c0b, incoming)) return true;

    const c1 = sha256Hex(`${idGoods}${idInvoice}${datePay}${amount}${secret}`).toLowerCase();
    if (constantTimeEquals(c1, incoming)) return true;

    const c2 = sha256Hex(`${idInvoice}${secret}`).toLowerCase();
    if (constantTimeEquals(c2, incoming)) return true;

    const keys = Object.keys(payload)
      .filter((k) => !['sign', 'signature', 'sha256'].includes(k.toLowerCase()))
      .sort();
    const dataStr = keys.map((k) => `${k}:${payload[k]}`).join(';') + ';';
    const c3 = hmacSha256Hex(secret, dataStr).toLowerCase();
    return constantTimeEquals(c3, incoming);
  }
}
