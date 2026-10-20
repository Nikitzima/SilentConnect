import { fetch } from 'sdk/fetch';
import {
  SETTINGS,
  TEST_PROFILE_NOTES,
  ADMIN_PROFILE_NOTES,
  PUBLIC_TRIAL_PROFILE_NOTES,
} from './config.js';
import {
  daysFromNow,
  hmacSha256Hex,
  normalizeUsername,
  nowTs,
  orderToProfileAlias,
  randomAlias,
  toXuiMs,
} from './security.js';

export const DEFAULT_NODES = [
  { code: 'nl', url: 'http://192.0.2.1:8080/api/bridge', timeoutMs: 3000 },
  { code: 'pl', url: 'http://198.51.100.1:8080/api/bridge', timeoutMs: 3000 },
];

export async function provisionWithFailover({
  order,
  nodes = DEFAULT_NODES,
  fetchFn = fetch,
  updateOrderStatusFn,
  notifyAdminsFn,
}) {
  const errors = [];

  for (const node of nodes) {
    try {
      const resp = await fetchFn(node.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'provision_profile',
          order_public_id: order.public_id,
          transport: order.transport,
          duration_days: order.duration_days,
        }),
      });

      if (!resp.ok) {
        errors.push(`${node.code}: HTTP ${resp.status}`);
        continue;
      }

      const data = await resp.json();
      const resPayload = data.result || data;
      if (!data.ok || !resPayload.sub_id || !resPayload.subscription_url) {
        errors.push(`${node.code}: invalid payload`);
        continue;
      }

      if (typeof updateOrderStatusFn === 'function') {
        await updateOrderStatusFn(order.public_id, 'delivered');
      }
      return {
        status: 'delivered',
        node: node.code,
        sub_id: resPayload.sub_id,
        subscription_url: resPayload.subscription_url,
      };
    } catch (err) {
      errors.push(`${node.code}: ${err.message}`);
    }
  }

  // Обе ноды недоступны: строго запрещено генерировать фейковый sub_id!
  if (typeof updateOrderStatusFn === 'function') {
    await updateOrderStatusFn(order.public_id, 'pending_provision');
  }
  if (typeof notifyAdminsFn === 'function') {
    await notifyAdminsFn(order.public_id, errors.join('; '));
  }

  return {
    status: 'pending_provision',
    node: null,
    sub_id: null,
    subscription_url: null,
    userMessage:
      '⏳ Оплата получена! Активация подписки поставлена в очередь и придёт автоматически в течение пары минут.',
  };
}

export class Provisioner {
  constructor(settingsOrOptions = SETTINGS, maybeStore) {
    if (settingsOrOptions && typeof settingsOrOptions === 'object' && ('store' in settingsOrOptions || 'fetch' in settingsOrOptions)) {
      this.settings = settingsOrOptions.settings || SETTINGS;
      this.store = settingsOrOptions.store || maybeStore;
      this._fetch = settingsOrOptions.fetch || null;
    } else {
      this.settings = settingsOrOptions || SETTINGS;
      this.store = maybeStore;
      this._fetch = null;
    }
  }

  _transportInboundId(transport) {
    if (transport === 'hybrid') {
      throw new Error('Hybrid transport must provision tcp and xhttp separately');
    }
    if (transport === 'xhttp') return this.settings.xuiXhttpInboundId;
    if (transport === 'tcp') return this.settings.xuiTcpInboundId;
    throw new Error(`Unsupported transport: ${transport}`);
  }

  get bridgeNodes() {
    if (Array.isArray(this.settings.bridgeNodes) && this.settings.bridgeNodes.length > 0) {
      return this.settings.bridgeNodes;
    }
    const nodes = [];
    const nlUrl = this.settings.bridgeUrl || this.settings.nlBridgeUrl;
    if (nlUrl) nodes.push({ code: 'nl', url: nlUrl, timeoutMs: 3000 });
    const plUrl = this.settings.bridgeUrlStandby || this.settings.plBridgeUrl;
    if (plUrl) nodes.push({ code: 'pl', url: plUrl, timeoutMs: 3000 });
    return nodes;
  }

  get hasBridge() {
    const secret = this.settings.clusterSyncSecret || this.settings.bridgeSecret;
    return Boolean(
      this.bridgeNodes.length > 0 &&
        secret &&
        secret !== 'CHANGE_ME_CLUSTER_SYNC_SECRET'
    );
  }

  async _callBridge(action, params = {}) {
    if (!this.hasBridge) {
      return null;
    }
    const ts = String(nowTs());
    const bodyObj = { action, ...params, ts: Number(ts) };
    const rawBody = JSON.stringify(bodyObj);
    const secret = this.settings.clusterSyncSecret || this.settings.bridgeSecret;
    const sig = hmacSha256Hex(secret, `${ts}.${rawBody}`);
    const fetchFunc = this._fetch || fetch;
    const errors = [];

    for (const node of this.bridgeNodes) {
      try {
        const res = await fetchFunc(node.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Bridge-Timestamp': ts,
            'X-Bridge-Signature': sig,
          },
          body: typeof fetchFunc.body?.text === 'function' ? fetchFunc.body.text(rawBody, 'application/json') : rawBody,
        });
        if (!res.ok) {
          const errText = await res.text();
          errors.push(`${node.code}: HTTP ${res.status}`);
          continue;
        }
        const data = await res.json();
        if (data && data.ok !== false) {
          return { ...data, node: node.code };
        }
      } catch (err) {
        errors.push(`${node.code}: ${err.message}`);
      }
    }

    console.error(`All bridge nodes failed for ${action}:`, errors.join('; '));
    return { ok: false, errors };
  }

  async findClientByEmail(email) {
    const bridgeRes = await this._callBridge('find_client_by_email', { email });
    if (bridgeRes && bridgeRes.found) {
      return bridgeRes.found;
    }
    const profile = await this.store.getProfileByXuiEmail(email);
    if (!profile || profile.status === 'deleted') return null;
    return {
      inbound_id: profile.xui_inbound_id,
      protocol: profile.transport,
      client: {
        id: profile.xui_client_id,
        email: profile.xui_email,
        subId: profile.xui_client_id,
        limitIp: profile.device_limit || this.settings.defaultDeviceLimit,
        expiryTime: toXuiMs(profile.expires_at),
        enable: profile.status === 'active',
      },
    };
  }

  async findClientBySubId(subId) {
    const bridgeRes = await this._callBridge('find_client_by_sub_id', { sub_id: subId });
    if (bridgeRes && (bridgeRes.found || bridgeRes.result)) {
      return bridgeRes.found || bridgeRes.result;
    }
    return null;
  }

  async getClientTraffic(email) {
    const bridgeRes = await this._callBridge('get_client_traffic', { email });
    if (bridgeRes && bridgeRes.traffic) return bridgeRes.traffic;
    const profile = await this.store.getProfileByXuiEmail(email);
    if (!profile) return null;
    return {
      email: profile.xui_email,
      enable: profile.status === 'active' ? 1 : 0,
      up: 0,
      down: Number(profile.awg_used_bytes || 0),
      expiry_time: toXuiMs(profile.expires_at),
      last_online: profile.last_renewed_at || profile.created_at,
    };
  }

  async listClientTraffic(limit = 20) {
    const bridgeRes = await this._callBridge('list_client_traffic', { limit });
    if (bridgeRes && Array.isArray(bridgeRes.rows)) {
      return bridgeRes.rows;
    }
    return [];
  }

  async getServerStatusText() {
    const bridgeRes = await this._callBridge('server_status', {});
    if (bridgeRes && bridgeRes.text) {
      return bridgeRes.text;
    }
    return [
      'Сервер SilentConnect (Telegram Serverless Runtime)',
      '',
      'tgcloud.isolate: active',
      'sdk/db (SQLite): active',
      `bridge (${this.settings.bridgeUrl}): ${this.hasBridge ? 'configured' : 'standalone mode'}`,
    ].join('\n');
  }

  async buildWarpConfig(subId, targetServer = 'nl') {
    const bridgeRes = await this._callBridge('build_warp_conf', {
      sub_id: subId,
      server_code: targetServer,
    });
    if (bridgeRes && bridgeRes.ok) {
      const payload = bridgeRes.result || bridgeRes;
      return {
        ok: true,
        conf_text: payload.conf_text || payload.conf || bridgeRes.conf || '',
        caption: payload.caption || bridgeRes.caption || null,
        server_code: payload.server_code || targetServer,
      };
    }
    throw new Error(
      bridgeRes?.error ||
        (bridgeRes?.errors ? bridgeRes.errors.join('; ') : 'Мост к VPN-ноде недоступен для генерации WARP конфига')
    );
  }

  async sendSubscriptionEmail(params) {
    await this._callBridge('send_subscription_email', params);
  }

  async _provisionProfile({
    transport,
    durationDays,
    profileMode,
    familyLabel = null,
    alias = null,
    notes = '',
    deviceLimit = 0,
  }) {
    const inboundId = this._transportInboundId(transport);
    const expiresAtS = daysFromNow(Number(durationDays));
    const effectiveAlias = alias || familyLabel || randomAlias();

    const bridgeRes = await this._callBridge('provision_profile', {
      order: {
        public_id: effectiveAlias,
        transport,
        duration_days: Number(durationDays),
        device_limit: Number(deviceLimit),
      },
      profile_mode: profileMode,
      family_label: familyLabel,
      alias: effectiveAlias,
      notes,
    });

    const resPayload = bridgeRes?.result || bridgeRes;
    const subId = resPayload?.sub_id;
    if (!subId) {
      // NEVER generate fake randomSubscriptionId() when nodes are offline
      return {
        ok: false,
        status: 'pending_provision',
        node: null,
        sub_id: null,
        subscription_url: null,
        userMessage:
          '⏳ Оплата получена! Активация подписки поставлена в очередь и придёт автоматически в течение пары минут.',
        errors: bridgeRes?.errors || ['all_nodes_offline'],
      };
    }

    const xuiClientId = resPayload?.xui_client_id || subId;
    const finalExpiresAt = Number(resPayload?.expires_at || expiresAtS);

    let profile = await this.store.getProfileByXuiEmail(effectiveAlias);
    if (!profile) {
      profile = await this.store.createProfile({
        xuiInboundId: inboundId,
        transport,
        profileMode,
        familyLabel,
        xuiEmail: effectiveAlias,
        xuiClientId,
        expiresAt: finalExpiresAt,
        notes,
        deviceLimit: Number(deviceLimit) || this.settings.defaultDeviceLimit,
      });
    }

    return {
      status: 'delivered',
      node: bridgeRes?.node || 'nl',
      profile,
      subscription_url: resPayload?.subscription_url || `${this.settings.subscriptionBaseUrl}/${subId}`,
      xui_email: effectiveAlias,
      sub_id: subId,
      expires_at: finalExpiresAt,
    };
  }

  async createProfileForOrder(order) {
    const orderMeta = order.meta_json || {};
    const renewalProfilePublicId = String(orderMeta.renewal_profile_public_id || '');
    if (renewalProfilePublicId) {
      const res = await this.renewProfile(renewalProfilePublicId, Number(order.duration_days), {
        deviceLimit: orderMeta.device_limit,
      });
      await this.store.linkOrderProfile(order.public_id, renewalProfilePublicId);
      return res;
    }

    const rawLimit = orderMeta.device_limit ?? this.settings.defaultDeviceLimit;
    const deviceLimit = Number(rawLimit == null ? this.settings.defaultDeviceLimit : rawLimit);

    if (String(order.transport) === 'hybrid') {
      return await this.createHybridProfileForOrder(order, { deviceLimit });
    }

    const alias = orderToProfileAlias(String(order.public_id));
    const result = await this._provisionProfile({
      transport: order.transport,
      durationDays: Number(order.duration_days),
      profileMode: order.profile_mode,
      familyLabel: order.family_label,
      alias,
      deviceLimit,
    });
    if (result.status === 'pending_provision') {
      await this.store.transitionOrder(order.public_id, 'pending_provision', {
        actor: 'system',
        reason: 'all_nodes_offline',
      });
      return result;
    }
    if (result.profile?.public_id) {
      await this.store.linkOrderProfile(order.public_id, result.profile.public_id);
    }
    return result;
  }

  async createHybridProfileForOrder(order, { deviceLimit }) {
    const orderPubId = String(order.public_id);
    const tcpAlias = orderToProfileAlias(orderPubId, 'tcp');
    const xhttpAlias = orderToProfileAlias(orderPubId, 'xhttp');

    const tcpResult = await this._provisionProfile({
      transport: 'tcp',
      durationDays: Number(order.duration_days),
      profileMode: String(order.profile_mode),
      familyLabel: null,
      alias: tcpAlias,
      deviceLimit,
    });
    if (tcpResult.status === 'pending_provision' || !tcpResult.profile) {
      await this.store.transitionOrder(order.public_id, 'pending_provision', {
        actor: 'system',
        reason: 'all_nodes_offline_hybrid_tcp',
      });
      return tcpResult;
    }

    const xhttpResult = await this._provisionProfile({
      transport: 'xhttp',
      durationDays: Number(order.duration_days),
      profileMode: String(order.profile_mode),
      familyLabel: null,
      alias: xhttpAlias,
      deviceLimit,
    });
    if (xhttpResult.status === 'pending_provision' || !xhttpResult.profile) {
      await this.store.transitionOrder(order.public_id, 'pending_provision', {
        actor: 'system',
        reason: 'all_nodes_offline_hybrid_xhttp',
      });
      return xhttpResult;
    }

    await this.store.linkOrderProfile(order.public_id, tcpResult.profile.public_id);
    const meta = {
      ...(order.meta_json || {}),
      hybrid: true,
      tcp_profile_public_id: tcpResult.profile.public_id,
      xhttp_profile_public_id: xhttpResult.profile.public_id,
      tcp_sub_id: tcpResult.sub_id,
      xhttp_sub_id: xhttpResult.sub_id,
    };
    await this.store.updateOrderMeta(order.public_id, meta);

    return {
      status: 'delivered',
      profile: tcpResult.profile,
      xhttp_profile: xhttpResult.profile,
      subscription_url: '',
      tcp_sub_id: tcpResult.sub_id,
      xhttp_sub_id: xhttpResult.sub_id,
      expires_at: Math.min(Number(tcpResult.expires_at), Number(xhttpResult.expires_at)),
    };
  }

  async renewProfile(profilePublicId, durationDays, { deviceLimit = null } = {}) {
    const profile = await this.store.getProfile(profilePublicId);
    if (!profile || profile.status === 'deleted') {
      throw new Error(`Profile ${profilePublicId} is not renewable`);
    }

    const baseExpiresAt = Math.max(nowTs(), Number(profile.expires_at || 0));
    const newExpiresAt = baseExpiresAt + Number(durationDays) * 86400;
    const effLimit = Number(deviceLimit ?? profile.device_limit ?? this.settings.defaultDeviceLimit);

    const bridgeRes = await this._callBridge('renew_profile', {
      profile_public_id: String(profilePublicId),
      xui_email: profile.xui_email,
      inbound_id: profile.xui_inbound_id,
      duration_days: Number(durationDays),
      new_expires_at: newExpiresAt,
      device_limit: effLimit,
    });

    if (!bridgeRes || bridgeRes.ok === false) {
      throw new Error(
        `Failed to renew profile ${profilePublicId} on VPN nodes: ${(bridgeRes?.errors || []).join('; ')}`
      );
    }

    const resPayload = bridgeRes.result || bridgeRes;
    const updatedProfile = await this.store.extendProfile(profilePublicId, newExpiresAt);
    const subId = resPayload?.sub_id || profile.xui_client_id;
    return {
      profile: updatedProfile || profile,
      subscription_url: resPayload?.subscription_url || `${this.settings.subscriptionBaseUrl}/${subId}`,
      xui_email: profile.xui_email,
      sub_id: subId,
      expires_at: Number(resPayload?.expires_at || newExpiresAt),
    };
  }

  async setProfileEnabled(profilePublicId, enabled) {
    const profile = await this.store.getProfile(profilePublicId);
    if (!profile || profile.status === 'deleted') {
      throw new Error(`Profile ${profilePublicId} is absent or deleted`);
    }
    const bridgeRes = await this._callBridge('set_profile_enabled', {
      profile_public_id: String(profilePublicId),
      xui_email: profile.xui_email,
      inbound_id: profile.xui_inbound_id,
      enabled: Boolean(enabled),
    });
    if (!bridgeRes || bridgeRes.ok === false) {
      throw new Error(`Failed to toggle profile ${profilePublicId} on VPN nodes`);
    }
    return {
      profile,
      xui_email: profile.xui_email,
      inbound_id: profile.xui_inbound_id,
      enabled: Boolean(enabled),
    };
  }

  async sendSubscriptionEmail(params) {
    const bridgeRes = await this._callBridge('send_subscription_email', params);
    return Boolean(bridgeRes && bridgeRes.ok);
  }

  async createPublicTrialProfile(user, transport = 'tcp') {
    const username = normalizeUsername(user?.username);
    const userId = Number(user?.id || 0);
    const aliasPrefix = username ? `trial-${username}` : `trial-id${userId}`;
    return await this._provisionProfile({
      transport,
      durationDays: 7,
      profileMode: 'anonymous',
      familyLabel: null,
      alias: randomAlias(aliasPrefix, 6),
      notes: PUBLIC_TRIAL_PROFILE_NOTES,
      deviceLimit: this.settings.defaultDeviceLimit,
    });
  }

  async createAdminProfile(transport, user) {
    const username = normalizeUsername(user?.username);
    const userId = Number(user?.id || 0);
    const aliasPrefix = username ? `admin-${username}` : `admin-id${userId}`;
    const familyLabel = randomAlias(aliasPrefix, 6);
    return await this._provisionProfile({
      transport,
      durationDays: 36500,
      profileMode: 'family',
      familyLabel,
      notes: ADMIN_PROFILE_NOTES,
    });
  }

  async createTestProfile(transport) {
    return await this._provisionProfile({
      transport,
      durationDays: 1,
      profileMode: 'anonymous',
      familyLabel: null,
      notes: TEST_PROFILE_NOTES,
    });
  }

  async createHybridTestProfile() {
    const aliasPrefix = randomAlias('hybrid-test', 6);
    const tcpResult = await this._provisionProfile({
      transport: 'tcp',
      durationDays: 1,
      profileMode: 'anonymous',
      familyLabel: null,
      alias: `${aliasPrefix}-tcp`,
      notes: TEST_PROFILE_NOTES,
    });
    const xhttpResult = await this._provisionProfile({
      transport: 'xhttp',
      durationDays: 1,
      profileMode: 'anonymous',
      familyLabel: null,
      alias: `${aliasPrefix}-xhttp`,
      notes: TEST_PROFILE_NOTES,
    });
    return {
      tcp: tcpResult,
      xhttp: xhttpResult,
      tcp_sub_id: tcpResult.sub_id,
      xhttp_sub_id: xhttpResult.sub_id,
      expires_at: Math.min(Number(tcpResult.expires_at), Number(xhttpResult.expires_at)),
    };
  }
}
