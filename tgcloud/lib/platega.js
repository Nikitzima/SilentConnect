import { fetch } from 'sdk/fetch';
import { SETTINGS } from './config.js';
import { constantTimeEquals } from './security.js';

export class PlategaClient {
  constructor(settings = SETTINGS) {
    this.merchantIdBot = String(settings.plategaMerchantIdBot || '').trim();
    this.merchantIdWeb = String(settings.plategaMerchantIdWeb || '').trim();
    this.secret = String(settings.plategaSecret || '').trim();
    this.secretBot = String(settings.plategaSecretBot || '').trim() || this.secret;
    this.secretWeb = String(settings.plategaSecretWeb || '').trim() || this.secret;
    this.baseUrl = String(settings.plategaBaseUrl || 'https://app.platega.io').replace(/\/+$/, '');
  }

  get isConfigured() {
    const hasSecret = Boolean(this.secret || this.secretBot || this.secretWeb);
    const hasMerchant = Boolean(this.merchantIdBot || this.merchantIdWeb);
    return hasSecret && hasMerchant;
  }

  _getMerchantCandidates(isBot = true) {
    const candidates = [];
    if (isBot) {
      if (this.merchantIdBot && this.secretBot) candidates.push([this.merchantIdBot, this.secretBot]);
      if (this.merchantIdWeb && this.secretWeb) candidates.push([this.merchantIdWeb, this.secretWeb]);
    } else {
      if (this.merchantIdWeb && this.secretWeb) candidates.push([this.merchantIdWeb, this.secretWeb]);
      if (this.merchantIdBot && this.secretBot) candidates.push([this.merchantIdBot, this.secretBot]);
    }
    return candidates;
  }

  async _request(method, path, merchantId, secret, payload = null) {
    const activeSecret = String(secret || this.secret || '').trim();
    if (!activeSecret) {
      throw new Error('Platega secret key (X-Secret) is not configured');
    }
    const url = `${this.baseUrl}/${String(path).replace(/^\/+/, '')}`;
    const headers = {
      'X-MerchantId': merchantId,
      'X-Secret': activeSecret,
      Accept: 'application/json',
      'User-Agent': 'SilentConnect-Serverless/2.0',
    };

    const options = {
      method: method.toUpperCase(),
      headers: { ...headers, 'Content-Type': 'application/json' },
    };
    if (payload !== null) {
      options.body =
        typeof fetch.body?.json === 'function' ? fetch.body.json(payload) : JSON.stringify(payload);
    }

    const res = await fetch(url, options);
    const text = await res.text();
    if (!res.ok) {
      const err = new Error(`Platega HTTP ${res.status} for ${path}: ${text.slice(0, 300)}`);
      err.statusCode = res.status;
      throw err;
    }
    if (!text) return {};
    return JSON.parse(text);
  }

  async createTransaction({
    amount,
    currency = 'RUB',
    description = 'Оплата сервиса',
    payload = '',
    returnUrl = '',
    failedUrl = '',
    metadata = {},
    isBot = true,
  }) {
    const body = {
      paymentDetails: {
        amount: Math.round(Number(amount)),
        currency: String(currency).toUpperCase(),
      },
      description: description || 'Оплата сервиса',
      payload: String(payload || ''),
      metadata: metadata || {},
    };
    if (returnUrl) body.return = returnUrl;
    if (failedUrl) body.failedUrl = failedUrl;

    const candidates = this._getMerchantCandidates(isBot);
    if (!candidates.length) {
      throw new Error(`Platega merchant ID or secret is not configured (isBot=${isBot})`);
    }

    let lastError = null;
    for (const [merchantId, secret] of candidates) {
      try {
        return await this._request('POST', '/v2/transaction/process', merchantId, secret, body);
      } catch (err) {
        lastError = err;
        if (err.statusCode !== 401) break;
      }
    }
    throw lastError || new Error('Failed to create Platega transaction');
  }

  async getTransactionStatus(transactionId, isBot = true) {
    if (!transactionId) throw new Error('transactionId is required');
    const candidates = this._getMerchantCandidates(isBot);
    if (!candidates.length) {
      throw new Error(`Platega merchant ID or secret is not configured (isBot=${isBot})`);
    }
    let lastError = null;
    for (const [merchantId, secret] of candidates) {
      try {
        return await this._request(
          'GET',
          `/transaction/${encodeURIComponent(String(transactionId))}`,
          merchantId,
          secret
        );
      } catch (err) {
        lastError = err;
        if (err.statusCode !== 401) break;
      }
    }
    throw lastError || new Error('Failed to check Platega transaction status');
  }

  verifyWebhookSignature(headers = {}) {
    const normalized = {};
    for (const [k, v] of Object.entries(headers || {})) {
      normalized[String(k).toLowerCase().replace(/[-_]/g, '')] = String(v || '').trim();
    }
    const merchantId = normalized.xmerchantid || '';
    const secret = normalized.xsecret || '';
    if (!merchantId || !secret) return false;

    if (merchantId === this.merchantIdBot) {
      const expected = this.secretBot || this.secret;
      return Boolean(expected && constantTimeEquals(secret, expected));
    }
    if (merchantId === this.merchantIdWeb) {
      const expected = this.secretWeb || this.secret;
      return Boolean(expected && constantTimeEquals(secret, expected));
    }
    return false;
  }
}
