import { AWG_TIER_QUOTAS_BYTES, SETTINGS } from './config.js';
import {
  hashSecret,
  hashToken,
  constantTimeEquals,
  maskedCode,
  nowTs,
  publicId,
  randomCode,
} from './security.js';

import { fetch } from 'sdk/fetch';
import { db } from 'sdk';
import * as sdkDbOps from 'sdk/db';
import { chatSessions } from '../schema.js';

const fallbackMemorySessions = new Map();

export const ORDER_TRANSITIONS = {
  waiting_payment: new Set(['provisioning', 'auto_provision', 'pending_provision', 'cancelled', 'expired']),
  auto_provision: new Set(['provisioning', 'pending_provision', 'failed', 'cancelled']),
  provisioning: new Set(['delivered', 'failed', 'waiting_payment', 'pending_provision']),
  pending_provision: new Set(['provisioning', 'delivered', 'failed', 'cancelled']),
  failed: new Set(['provisioning', 'delivered', 'cancelled']),
  delivered: new Set(['cancelled']),
  cancelled: new Set(),
  expired: new Set(),
};

export const TERMINAL_ORDER_STATES = new Set(['delivered', 'cancelled', 'expired']);

export class OrderStateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OrderStateError';
  }
}

function toSnakeOrder(row) {
  if (!row) return null;
  return {
    id: row.id,
    public_id: row.public_id,
    kind: row.kind,
    status: row.status,
    transport: row.transport,
    duration_days: Number(row.duration_days),
    profile_mode: row.profile_mode,
    family_label: row.family_label,
    base_price_rub: Number(row.base_price_rub),
    final_price_rub: Number(row.final_price_rub),
    promo_id: row.promo_id != null ? Number(row.promo_id) : null,
    invite_id: row.invite_id != null ? Number(row.invite_id) : null,
    customer_chat_id: row.customer_chat_id ? String(row.customer_chat_id) : null,
    customer_email: String(row.customer_email || ''),
    manager_chat_id: row.manager_chat_id ? String(row.manager_chat_id) : null,
    manager_message_id: row.manager_message_id != null ? Number(row.manager_message_id) : null,
    privacy_ack: row.privacy_ack ? 1 : 0,
    loss_policy_ack: row.loss_policy_ack ? 1 : 0,
    terms_version: String(row.terms_version || ''),
    provisioned_profile_id: row.provisioned_profile_id != null ? Number(row.provisioned_profile_id) : null,
    created_at: Number(row.created_at),
    updated_at: Number(row.updated_at),
    closed_at: row.closed_at != null ? Number(row.closed_at) : null,
    meta_json: typeof row.meta_json === 'string'
      ? (JSON.parse(row.meta_json || '{}'))
      : (row.meta_json || {}),
    external_id: row.external_id || null,
    web_token_hash: row.web_token_hash || null,
    version: row.version != null ? Number(row.version) : 1,
  };
}

function toSnakeProfile(row) {
  if (!row) return null;
  return {
    id: row.id,
    public_id: row.public_id,
    xui_inbound_id: Number(row.xui_inbound_id),
    transport: row.transport,
    profile_mode: row.profile_mode,
    family_label: row.family_label,
    xui_email: row.xui_email,
    xui_client_id: row.xui_client_id,
    status: row.status,
    created_at: Number(row.created_at),
    expires_at: Number(row.expires_at),
    last_renewed_at: Number(row.last_renewed_at),
    deleted_at: row.deleted_at != null ? Number(row.deleted_at) : null,
    notes: row.notes,
    awg_quota_bytes: row.awg_quota_bytes != null ? Number(row.awg_quota_bytes) : 0,
    awg_used_bytes: row.awg_used_bytes != null ? Number(row.awg_used_bytes) : 0,
    awg_reset_at: row.awg_reset_at != null ? Number(row.awg_reset_at) : null,
    device_limit: row.device_limit != null ? Number(row.device_limit) : 3,
  };
}

function toSnakePromo(row) {
  if (!row) return null;
  return {
    id: row.id,
    code_hash: row.code_hash,
    code_preview: row.code_preview,
    promo_type: row.promo_type,
    transport: row.transport,
    duration_days: Number(row.duration_days),
    duration_months: row.duration_months != null ? Number(row.duration_months) : null,
    discount_percent: Number(row.discount_percent),
    fixed_price_rub: row.fixed_price_rub != null ? Number(row.fixed_price_rub) : null,
    device_limit: Number(row.device_limit || 3),
    profile_mode: row.profile_mode,
    family_label: row.family_label,
    max_uses: Number(row.max_uses),
    used_count: Number(row.used_count || 0),
    expires_at: row.expires_at != null ? Number(row.expires_at) : null,
    enabled: row.enabled ? 1 : 0,
    created_at: Number(row.created_at),
    last_used_at: row.last_used_at != null ? Number(row.last_used_at) : null,
  };
}

function toSnakeInvite(row) {
  if (!row) return null;
  return {
    id: row.id,
    code_hash: row.code_hash,
    code_preview: row.code_preview,
    purpose: row.purpose,
    max_uses: Number(row.max_uses),
    used_count: Number(row.used_count || 0),
    expires_at: row.expires_at != null ? Number(row.expires_at) : null,
    enabled: row.enabled ? 1 : 0,
    created_at: Number(row.created_at),
    note: row.note,
  };
}

export class Store {
  constructor(options = {}) {
    this.settings = options.settings || SETTINGS;
    this.fetch = options.fetch || fetch;
    const env = globalThis.process?.env || {};
    this.tursoUrl = options.tursoUrl || this.settings.tursoUrl || env.TURSO_DATABASE_URL || '';
    this.tursoToken = options.tursoToken || this.settings.tursoToken || env.TURSO_AUTH_TOKEN || '';
    this._memorySessions = fallbackMemorySessions;
  }

  // --- Turso HTTP Pipeline Executor (/v2/pipeline) ---
  async executeTurso(sql, args = []) {
    const encodedArgs = (args || []).map((val) => {
      if (val === null || val === undefined) return { type: 'null' };
      if (typeof val === 'boolean') return { type: 'integer', value: val ? '1' : '0' };
      if (typeof val === 'number') {
        return Number.isInteger(val)
          ? { type: 'integer', value: String(val) }
          : { type: 'float', value: val };
      }
      if (typeof val === 'object') {
        return { type: 'text', value: JSON.stringify(val) };
      }
      return { type: 'text', value: String(val) };
    });

    if (!this.tursoUrl) {
      throw new Error('TURSO_DATABASE_URL is not configured');
    }

    const baseUrl = this.tursoUrl.trim().replace(/^libsql:\/\//i, 'https://').replace(/\/+$/, '');
    const endpoint = `${baseUrl}/v2/pipeline`;
    const f = this.fetch || fetch;
    const payloadObj = {
      requests: [
        { type: 'execute', stmt: { sql, args: encodedArgs } },
        { type: 'close' },
      ],
    };

    let resp;
    try {
      resp = await f(endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.tursoToken}`,
          'Content-Type': 'application/json',
        },
        body: typeof f?.body?.json === 'function' ? f.body.json(payloadObj) : JSON.stringify(payloadObj),
      });
    } catch (err) {
      console.error('TURSO FETCH FAILED:', endpoint, err?.message || err);
      throw err;
    }

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      throw new Error(`Turso HTTP ${resp.status}: ${errText}`);
    }

    const data = await resp.json();
    const resultObj = data?.results?.[0];
    if (!resultObj) {
      throw new Error('Invalid Turso pipeline response: empty results');
    }
    if (resultObj.type === 'error') {
      throw new Error(`Turso query error: ${resultObj.error?.message || JSON.stringify(resultObj.error)}`);
    }

    const execRes = resultObj.response?.result;
    if (!execRes) {
      return { rows: [], affectedRowCount: 0, lastInsertRowid: null };
    }

    const cols = (execRes.cols || []).map((c) => c.name);
    const rows = (execRes.rows || []).map((rowArr) => {
      const obj = {};
      cols.forEach((colName, idx) => {
        const cell = rowArr[idx];
        let val = null;
        if (cell && cell.type !== 'null') {
          if (cell.type === 'integer') {
            val = Number(cell.value);
          } else if (cell.type === 'float') {
            val = Number(cell.value);
          } else {
            val = cell.value;
          }
        }
        if (typeof colName === 'string' && colName.endsWith('_json')) {
          if (typeof val === 'string') {
            try {
              val = JSON.parse(val || '{}');
            } catch {
              val = {};
            }
          } else if (!val) {
            val = {};
          }
        }
        obj[colName] = val;
      });
      return obj;
    });

    return {
      rows,
      affectedRowCount: execRes.affected_row_count || 0,
      lastInsertRowid: execRes.last_insert_rowid ? Number(execRes.last_insert_rowid) : null,
    };
  }

  async queryTurso(sql, args = []) {
    const res = await this.executeTurso(sql, args);
    return res.rows;
  }

  async getTurso(sql, args = []) {
    const res = await this.executeTurso(sql, args);
    return res.rows[0] || null;
  }

  // --- Локальные сессии чатов Telegram (через db из 'sdk' и таблицу chatSessions из '../schema.js') ---
  async getSession(chatId) {
    if (db && sdkDbOps?.eq && chatSessions) {
      const row = await db
        .select()
        .from(chatSessions)
        .where(sdkDbOps.eq(chatSessions.chatId, String(chatId)))
        .get();
      if (!row) return null;
      return {
        chat_id: row.chatId,
        scope: row.scope,
        state: row.state,
        context_json:
          typeof row.contextJson === 'string'
            ? JSON.parse(row.contextJson || '{}')
            : (row.contextJson || {}),
        updated_at: row.updatedAt,
      };
    }
    const mem = this._memorySessions.get(String(chatId));
    return mem ? { ...mem } : null;
  }

  async setSession(chatId, scope, state, context = {}) {
    const now = nowTs();
    const payload = context || {};
    if (db && chatSessions) {
      await db
        .insert(chatSessions)
        .values({
          chatId: String(chatId),
          scope: String(scope),
          state: String(state),
          contextJson: payload,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: chatSessions.chatId,
          set: {
            scope: String(scope),
            state: String(state),
            contextJson: payload,
            updatedAt: now,
          },
        })
        .run();
      return;
    }
    this._memorySessions.set(String(chatId), {
      chat_id: String(chatId),
      scope: String(scope),
      state: String(state),
      context_json: payload,
      updated_at: now,
    });
  }

  async clearSession(chatId) {
    if (db && sdkDbOps?.eq && chatSessions) {
      await db.delete(chatSessions).where(sdkDbOps.eq(chatSessions.chatId, String(chatId))).run();
      return;
    }
    this._memorySessions.delete(String(chatId));
  }

  async listChatIdsByScope(scope) {
    if (db && sdkDbOps?.eq && sdkDbOps?.desc && chatSessions) {
      const rows = await db
        .select({ chatId: chatSessions.chatId })
        .from(chatSessions)
        .where(sdkDbOps.eq(chatSessions.scope, String(scope)))
        .orderBy(sdkDbOps.desc(chatSessions.updatedAt))
        .all();
      const result = rows.map((r) => String(r.chatId)).filter(Boolean);
      if (!result.length && scope === 'admin') {
        for (const uid of this.settings.adminUserIds || []) {
          const s = String(uid);
          if (s && !result.includes(s)) result.push(s);
        }
      }
      return result;
    }
    const result = [];
    for (const s of this._memorySessions.values()) {
      if (s.scope === String(scope) && !result.includes(s.chat_id)) {
        result.push(s.chat_id);
      }
    }
    if (!result.length && scope === 'admin') {
      for (const uid of this.settings.adminUserIds || []) {
        const s = String(uid);
        if (s && !result.includes(s)) result.push(s);
      }
    }
    return result;
  }

  // --- Telegram Users (Turso) ---
  async upsertTelegramUser({ user, chatId }) {
    const userId = String(user?.id || '');
    if (!userId) return;
    const now = nowTs();
    const username = String(user.username || '').trim() || null;
    const firstName = String(user.first_name || '').trim() || null;
    const lastName = String(user.last_name || '').trim() || null;
    const isBot = user.is_bot ? 1 : 0;

    await this.executeTurso(
      `INSERT INTO telegram_users (user_id, chat_id, username, first_name, last_name, is_bot, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         chat_id = excluded.chat_id,
         username = excluded.username,
         first_name = excluded.first_name,
         last_name = excluded.last_name,
         is_bot = excluded.is_bot,
         last_seen_at = excluded.last_seen_at`,
      [userId, String(chatId), username, firstName, lastName, isBot, now, now]
    );
  }

  // --- Инвайт-токены (Turso) ---
  async createInvite({ maxUses = 1, expiresAt = null, note = '' } = {}) {
    const code = randomCode('INV');
    const now = nowTs();
    const res = await this.executeTurso(
      `INSERT INTO invite_tokens (code_hash, code_preview, max_uses, expires_at, created_at, note)
       VALUES (?, ?, ?, ?, ?, ?) RETURNING *`,
      [hashSecret(code), maskedCode(code), Number(maxUses), expiresAt != null ? Number(expiresAt) : null, now, note ? String(note).trim() : null]
    );
    return [code, toSnakeInvite(res.rows[0])];
  }

  async findValidInvite(code) {
    const now = nowTs();
    const row = await this.getTurso(
      `SELECT * FROM invite_tokens
       WHERE code_hash = ? AND enabled = 1 AND used_count < max_uses AND (expires_at IS NULL OR expires_at > ?)
       LIMIT 1`,
      [hashSecret(code), now]
    );
    return toSnakeInvite(row);
  }

  async consumeInvite(codeOrId) {
    const now = nowTs();
    const isNumeric = typeof codeOrId === 'number' || /^\d+$/.test(String(codeOrId));
    const whereSql = isNumeric ? 'id = ?' : 'code_hash = ?';
    const param = isNumeric ? Number(codeOrId) : hashSecret(String(codeOrId));

    const res = await this.executeTurso(
      `UPDATE invite_tokens
       SET used_count = used_count + 1
       WHERE ${whereSql} AND enabled = 1 AND used_count < max_uses AND (expires_at IS NULL OR expires_at > ?)
       RETURNING *`,
      [param, now]
    );
    return toSnakeInvite(res.rows[0]);
  }

  async restoreInvite(inviteId) {
    const res = await this.executeTurso(
      `UPDATE invite_tokens
       SET used_count = MAX(0, used_count - 1)
       WHERE id = ?
       RETURNING *`,
      [Number(inviteId)]
    );
    return toSnakeInvite(res.rows[0]);
  }

  // --- Промокоды (Turso) ---
  async createPromoCode({
    promoType = 'fixed',
    transport,
    durationDays,
    discountPercent,
    durationMonths = null,
    fixedPriceRub = null,
    deviceLimit = 3,
    profileMode,
    familyLabel = null,
    maxUses = 1,
    expiresAt = null,
  }) {
    const code = randomCode('PROMO');
    const now = nowTs();
    const res = await this.executeTurso(
      `INSERT INTO promo_codes (
        code_hash, code_preview, promo_type, transport, duration_days, duration_months,
        discount_percent, fixed_price_rub, device_limit, profile_mode, family_label,
        max_uses, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`,
      [
        hashSecret(code), maskedCode(code), promoType, transport, Number(durationDays),
        durationMonths != null ? Number(durationMonths) : null, Number(discountPercent),
        fixedPriceRub != null ? Number(fixedPriceRub) : null, Number(deviceLimit || 3),
        profileMode, familyLabel, Number(maxUses), expiresAt != null ? Number(expiresAt) : null, now
      ]
    );
    return [code, toSnakePromo(res.rows[0])];
  }

  async getValidPromoById(promoId) {
    const now = nowTs();
    const row = await this.getTurso(
      `SELECT * FROM promo_codes
       WHERE id = ? AND enabled = 1 AND used_count < max_uses AND (expires_at IS NULL OR expires_at > ?)
       LIMIT 1`,
      [Number(promoId), now]
    );
    return toSnakePromo(row);
  }

  async findValidPromo(code) {
    const now = nowTs();
    const row = await this.getTurso(
      `SELECT * FROM promo_codes
       WHERE code_hash = ? AND enabled = 1 AND used_count < max_uses AND (expires_at IS NULL OR expires_at > ?)
       LIMIT 1`,
      [hashSecret(String(code).trim()), now]
    );
    return toSnakePromo(row);
  }

  async getOpenOrderForPromo(promoId) {
    const row = await this.getTurso(
      `SELECT * FROM orders
       WHERE promo_id = ? AND closed_at IS NULL AND status IN ('waiting_payment', 'auto_provision')
       ORDER BY created_at ASC, id ASC LIMIT 1`,
      [Number(promoId)]
    );
    return toSnakeOrder(row);
  }

  async consumePromoCode(codeOrId) {
    const now = nowTs();
    const isNumeric = typeof codeOrId === 'number' || /^\d+$/.test(String(codeOrId));
    const whereSql = isNumeric ? 'id = ?' : 'code_hash = ?';
    const param = isNumeric ? Number(codeOrId) : hashSecret(String(codeOrId));

    const res = await this.executeTurso(
      `UPDATE promo_codes
       SET used_count = used_count + 1, last_used_at = ?
       WHERE ${whereSql} AND enabled = 1 AND used_count < max_uses AND (expires_at IS NULL OR expires_at > ?)
       RETURNING *`,
      [now, param, now]
    );
    return toSnakePromo(res.rows[0]);
  }

  async restorePromoCode(promoId) {
    const res = await this.executeTurso(
      `UPDATE promo_codes
       SET used_count = MAX(0, used_count - 1)
       WHERE id = ?
       RETURNING *`,
      [Number(promoId)]
    );
    return toSnakePromo(res.rows[0]);
  }

  // --- Заказы (Turso) ---
  async createOrder({
    kind,
    status,
    transport,
    durationDays,
    profileMode,
    familyLabel = null,
    basePriceRub,
    finalPriceRub,
    promoId = null,
    inviteId = null,
    customerChatId = null,
    privacyAck = true,
    lossPolicyAck = true,
    termsVersion = SETTINGS.termsVersion,
    customerEmail = '',
    externalId = null,
    meta = {},
  }) {
    const now = nowTs();
    const mergedMeta = { ...(meta || {}) };
    if (customerEmail) mergedMeta.customer_email = customerEmail;
    const pub = publicId('ord', 12);

    const res = await this.executeTurso(
      `INSERT INTO orders (
        public_id, kind, status, transport, duration_days, profile_mode, family_label,
        base_price_rub, final_price_rub, promo_id, invite_id, customer_chat_id, customer_email,
        privacy_ack, loss_policy_ack, terms_version, created_at, updated_at, meta_json, external_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      RETURNING *`,
      [
        pub, kind, status, transport, Number(durationDays), profileMode, familyLabel,
        Number(basePriceRub), Number(finalPriceRub), promoId != null ? Number(promoId) : null,
        inviteId != null ? Number(inviteId) : null, customerChatId != null ? String(customerChatId) : null,
        String(customerEmail || ''), privacyAck ? 1 : 0, lossPolicyAck ? 1 : 0, String(termsVersion),
        now, now, mergedMeta, externalId ? String(externalId).trim() : null
      ]
    );
    return toSnakeOrder(res.rows[0]);
  }

  async getOrder(publicIdValue) {
    const row = await this.getTurso(
      `SELECT * FROM orders WHERE public_id = ? LIMIT 1`,
      [String(publicIdValue)]
    );
    return toSnakeOrder(row);
  }

  async getOrderByWebToken(publicIdValue, token) {
    const order = await this.getOrder(publicIdValue);
    if (!order) return null;
    const stored = String(order.web_token_hash || '');
    if (!stored) {
      const legacy = String(order.meta_json?.web_token || '');
      if (legacy && constantTimeEquals(legacy, token)) return order;
      return null;
    }
    if (constantTimeEquals(stored, hashToken(token, 'order_web'))) {
      return order;
    }
    return null;
  }

  async updateOrderMeta(publicIdValue, meta) {
    const clean = { ...(meta || {}) };
    delete clean.web_token;
    await this.executeTurso(
      `UPDATE orders SET meta_json = ?, updated_at = ? WHERE public_id = ?`,
      [clean, nowTs(), String(publicIdValue)]
    );
  }

  async transitionOrder(
    publicIdValue,
    toStatus,
    { expectedFrom = null, actor = 'system', reason = null } = {}
  ) {
    if (!ORDER_TRANSITIONS[toStatus]) {
      throw new OrderStateError(`Unknown order status ${toStatus}`);
    }
    let allowedFrom = Object.entries(ORDER_TRANSITIONS)
      .filter(([, targets]) => targets.has(toStatus))
      .map(([state]) => state);

    if (expectedFrom) {
      const expSet = new Set(expectedFrom);
      allowedFrom = allowedFrom.filter((s) => expSet.has(s));
    }
    if (!allowedFrom.length) {
      throw new OrderStateError(`No legal transition into ${toStatus}`);
    }

    const current = await this.getOrder(publicIdValue);
    if (!current) {
      throw new OrderStateError(`Order ${publicIdValue} not found`);
    }
    const fromStatus = String(current.status);
    if (!allowedFrom.includes(fromStatus)) {
      throw new OrderStateError(`Illegal transition for ${publicIdValue}: ${fromStatus} -> ${toStatus}`);
    }

    const now = nowTs();
    const closed = TERMINAL_ORDER_STATES.has(toStatus);
    const closedAtVal = closed ? (current.closed_at || now) : current.closed_at;

    const placeholders = allowedFrom.map(() => '?').join(', ');
    const res = await this.executeTurso(
      `UPDATE orders
       SET status = ?, updated_at = ?, version = version + 1, closed_at = ?
       WHERE public_id = ? AND status IN (${placeholders})
       RETURNING *`,
      [toStatus, now, closedAtVal, String(publicIdValue), ...allowedFrom]
    );

    if (!res.rows.length) {
      throw new OrderStateError(`Concurrent transition conflict for ${publicIdValue}`);
    }

    await this.executeTurso(
      `INSERT INTO order_state_log (order_public_id, from_status, to_status, actor, reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [String(publicIdValue), fromStatus, toStatus, String(actor), reason ? String(reason) : null, now]
    );

    return toSnakeOrder(res.rows[0]);
  }

  async updateOrderStatus(publicIdValue, status, { actor = 'legacy', reason = null } = {}) {
    return await this.transitionOrder(publicIdValue, status, { actor, reason });
  }

  async linkOrderProfile(orderPublicId, profilePublicId) {
    const pRow = await this.getTurso(
      `SELECT id FROM profiles WHERE public_id = ? LIMIT 1`,
      [String(profilePublicId)]
    );
    if (!pRow) throw new Error(`Profile ${profilePublicId} not found`);
    await this.executeTurso(
      `UPDATE orders SET provisioned_profile_id = ?, updated_at = ? WHERE public_id = ?`,
      [pRow.id, nowTs(), String(orderPublicId)]
    );
  }

  async attachManagerMessage(publicIdValue, managerChatId, managerMessageId) {
    await this.executeTurso(
      `UPDATE orders SET manager_chat_id = ?, manager_message_id = ?, updated_at = ? WHERE public_id = ?`,
      [String(managerChatId), Number(managerMessageId), nowTs(), String(publicIdValue)]
    );
  }

  async getOrderByManagerMessage(managerChatId, managerMessageId) {
    const row = await this.getTurso(
      `SELECT * FROM orders WHERE manager_chat_id = ? AND manager_message_id = ? ORDER BY updated_at DESC LIMIT 1`,
      [String(managerChatId), Number(managerMessageId)]
    );
    return toSnakeOrder(row);
  }

  async clearOrderCustomerContact(publicIdValue) {
    await this.executeTurso(
      `UPDATE orders SET customer_chat_id = NULL, updated_at = ? WHERE public_id = ?`,
      [nowTs(), String(publicIdValue)]
    );
  }

  async getLatestOrderForChat(chatId, { statuses = null } = {}) {
    let sql = 'SELECT * FROM orders WHERE customer_chat_id = ?';
    const args = [String(chatId)];
    if (statuses && statuses.length) {
      sql += ` AND status IN (${statuses.map(() => '?').join(', ')})`;
      args.push(...statuses);
    }
    sql += ' ORDER BY created_at DESC, id DESC LIMIT 1';
    const row = await this.getTurso(sql, args);
    return toSnakeOrder(row);
  }

  async getActiveOrderForChat(chatId, { statuses = ['waiting_payment', 'auto_provision'] } = {}) {
    let sql = 'SELECT * FROM orders WHERE customer_chat_id = ? AND closed_at IS NULL';
    const args = [String(chatId)];
    if (statuses && statuses.length) {
      sql += ` AND status IN (${statuses.map(() => '?').join(', ')})`;
      args.push(...statuses);
    }
    sql += ' ORDER BY created_at DESC, id DESC LIMIT 1';
    const row = await this.getTurso(sql, args);
    return toSnakeOrder(row);
  }

  async listOpenOrdersForChat(chatId, { statuses = ['waiting_payment'] } = {}) {
    let sql = 'SELECT * FROM orders WHERE customer_chat_id = ? AND closed_at IS NULL';
    const args = [String(chatId)];
    if (statuses && statuses.length) {
      sql += ` AND status IN (${statuses.map(() => '?').join(', ')})`;
      args.push(...statuses);
    }
    sql += ' ORDER BY created_at ASC, id ASC';
    const rows = await this.queryTurso(sql, args);
    return rows.map(toSnakeOrder);
  }

  async cancelOpenOrdersForChat(chatId, { statuses = ['waiting_payment'] } = {}) {
    const openOrders = await this.listOpenOrdersForChat(chatId, { statuses });
    if (!openOrders.length) return [];
    const now = nowTs();
    const ids = openOrders.map((o) => o.public_id);
    const placeholders = ids.map(() => '?').join(', ');
    await this.executeTurso(
      `UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE public_id IN (${placeholders})`,
      [now, now, ...ids]
    );
    return openOrders;
  }

  async expireWaitingPaymentOrdersForChat(chatId, { olderThanSeconds }) {
    const openOrders = await this.listOpenOrdersForChat(chatId, { statuses: ['waiting_payment'] });
    if (!openOrders.length) return [];
    const cutoff = nowTs() - Number(olderThanSeconds);
    const expired = openOrders.filter((o) => Number(o.created_at || 0) <= cutoff);
    if (!expired.length) return [];
    const now = nowTs();
    const ids = expired.map((o) => o.public_id);
    const placeholders = ids.map(() => '?').join(', ');
    await this.executeTurso(
      `UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE public_id IN (${placeholders})`,
      [now, now, ...ids]
    );
    return expired;
  }

  // --- Профили (Turso) ---
  async createProfile({
    xuiInboundId,
    transport,
    profileMode,
    familyLabel = null,
    xuiEmail,
    xuiClientId,
    expiresAt,
    notes = '',
    awgQuotaBytes = 0,
    awgResetAt = null,
    deviceLimit = null,
  }) {
    const now = nowTs();
    const pub = publicId('prf');
    const resetAt = awgResetAt != null ? Number(awgResetAt) : Number(expiresAt);
    const quotaVal = Number(awgQuotaBytes || 0);
    let effLimit = 3;
    if (deviceLimit != null) {
      effLimit = Math.max(1, Math.min(9, Number(deviceLimit)));
    } else if (quotaVal >= AWG_TIER_QUOTAS_BYTES[9]) {
      effLimit = 9;
    } else if (quotaVal >= AWG_TIER_QUOTAS_BYTES[6]) {
      effLimit = 6;
    }

    const res = await this.executeTurso(
      `INSERT INTO profiles (
        public_id, xui_inbound_id, transport, profile_mode, family_label,
        xui_email, xui_client_id, status, created_at, expires_at,
        last_renewed_at, notes, awg_quota_bytes, awg_used_bytes, awg_reset_at, device_limit
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, 0, ?, ?)
      RETURNING *`,
      [
        pub, Number(xuiInboundId), transport, profileMode, familyLabel,
        String(xuiEmail), String(xuiClientId), now, Number(expiresAt),
        now, notes || null, quotaVal, resetAt, effLimit
      ]
    );
    return toSnakeProfile(res.rows[0]);
  }

  async getProfile(publicIdValue) {
    const row = await this.getTurso(
      `SELECT * FROM profiles WHERE public_id = ? LIMIT 1`,
      [String(publicIdValue)]
    );
    return toSnakeProfile(row);
  }

  async getProfileByXuiEmail(xuiEmail) {
    const row = await this.getTurso(
      `SELECT * FROM profiles WHERE xui_email = ? ORDER BY id DESC LIMIT 1`,
      [String(xuiEmail)]
    );
    return toSnakeProfile(row);
  }

  async ensureProfileForXuiClient(xuiInboundId, client, transport = 'tcp') {
    const email = String(client?.email || '').trim();
    if (!email) throw new Error('XUI client has no email');
    const existing = await this.getProfileByXuiEmail(email);
    if (existing) return existing;

    const expiryMs = Number(client.expiryTime || 0);
    const expiresAt = expiryMs > 0 ? Math.floor(expiryMs / 1000) : nowTs() + 30 * 86400;
    const clientId = String(client.id || client.password || email);
    const mode = !(email.startsWith('anon-') || email.startsWith('ord_')) ? 'family' : 'anonymous';

    return await this.createProfile({
      xuiInboundId: Number(xuiInboundId),
      transport,
      profileMode: mode,
      familyLabel: mode === 'family' ? email : null,
      xuiEmail: email,
      xuiClientId: clientId,
      expiresAt,
      notes: 'auto_sync_from_xui',
    });
  }

  async extendProfile(profilePublicId, expiresAt, { resetAwgQuota = true } = {}) {
    const now = nowTs();
    let sql = `UPDATE profiles SET expires_at = ?, last_renewed_at = ?, status = 'active', deleted_at = NULL`;
    const args = [Number(expiresAt), now];
    if (resetAwgQuota) {
      sql += `, awg_used_bytes = 0, awg_reset_at = ?`;
      args.push(Number(expiresAt));
    }
    sql += ` WHERE public_id = ? AND status != 'deleted' RETURNING *`;
    args.push(String(profilePublicId));
    const res = await this.executeTurso(sql, args);
    return toSnakeProfile(res.rows[0]);
  }

  async markProfileDeleted(publicIdValue) {
    await this.executeTurso(
      `UPDATE profiles SET status = 'deleted', deleted_at = ? WHERE public_id = ? AND status != 'deleted'`,
      [nowTs(), String(publicIdValue)]
    );
  }

  async markProfileExpired(publicIdValue) {
    await this.executeTurso(
      `UPDATE profiles SET status = 'expired' WHERE public_id = ? AND status = 'active'`,
      [String(publicIdValue)]
    );
  }

  async getProfileOwner(profilePublicId) {
    return await this.getTurso(
      `SELECT * FROM profile_owners WHERE profile_public_id = ? LIMIT 1`,
      [String(profilePublicId)]
    );
  }

  async linkProfileOwner({ profilePublicId, userId, chatId, sourceOrderPublicId = null }) {
    const now = nowTs();
    await this.executeTurso(
      `INSERT INTO profile_owners (profile_public_id, user_id, chat_id, source_order_public_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(profile_public_id) DO UPDATE SET
         user_id = excluded.user_id,
         chat_id = excluded.chat_id,
         source_order_public_id = COALESCE(excluded.source_order_public_id, profile_owners.source_order_public_id),
         updated_at = excluded.updated_at`,
      [String(profilePublicId), String(userId), String(chatId), sourceOrderPublicId || null, now, now]
    );
  }

  async getOrderForProfile(profilePublicId) {
    const p = await this.getProfile(profilePublicId);
    if (!p) return null;
    const row = await this.getTurso(
      `SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`,
      [p.id]
    );
    return toSnakeOrder(row);
  }

  async getProfileForOrder(orderPublicId) {
    const ord = await this.getOrder(orderPublicId);
    if (!ord || !ord.provisioned_profile_id) return null;
    const row = await this.getTurso(
      `SELECT * FROM profiles WHERE id = ? LIMIT 1`,
      [Number(ord.provisioned_profile_id)]
    );
    return toSnakeProfile(row);
  }

  async getLatestRenewableProfileForUser(userId, { excludedNotes = [] } = {}) {
    const rows = await this.queryTurso(
      `SELECT p.* FROM profiles p
       INNER JOIN profile_owners o ON o.profile_public_id = p.public_id
       WHERE o.user_id = ? AND p.status != 'deleted'
       ORDER BY o.id DESC`,
      [String(userId)]
    );
    if (!rows.length) return null;
    const excludedSet = new Set(excludedNotes || []);
    const now = nowTs();
    const filtered = rows
      .map(toSnakeProfile)
      .filter((p) => p && (!p.notes || !excludedSet.has(p.notes)));
    if (!filtered.length) return null;
    filtered.sort((a, b) => {
      const aActive = a.expires_at >= now ? 0 : 1;
      const bActive = b.expires_at >= now ? 0 : 1;
      if (aActive !== bActive) return aActive - bActive;
      return b.id - a.id;
    });
    return filtered[0];
  }

  // --- Действия администраторов (Turso) ---
  async recordAdminAction({ actionType, targetType, targetPublicId, actor, meta = {} }) {
    await this.executeTurso(
      `INSERT INTO admin_actions (action_type, target_type, target_public_id, actor, created_at, meta_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [String(actionType), String(targetType), String(targetPublicId), String(actor), nowTs(), meta || {}]
    );
  }

  async getLastAdminAction({ actionType, targetType, targetPublicId }) {
    const row = await this.getTurso(
      `SELECT * FROM admin_actions
       WHERE action_type = ? AND target_type = ? AND target_public_id = ?
       ORDER BY created_at DESC, id DESC LIMIT 1`,
      [String(actionType), String(targetType), String(targetPublicId)]
    );
    return row ? {
      id: row.id,
      action_type: row.action_type,
      target_type: row.target_type,
      target_public_id: row.target_public_id,
      actor: row.actor,
      created_at: Number(row.created_at),
      meta_json: typeof row.meta_json === 'string' ? JSON.parse(row.meta_json || '{}') : (row.meta_json || {}),
    } : null;
  }

  // --- Пробный период (Turso) ---
  async getTrialRedemption(userId) {
    return await this.getTurso(
      `SELECT * FROM trial_redemptions WHERE user_id = ? LIMIT 1`,
      [String(userId)]
    );
  }

  async claimTrialRedemption({ userId, chatId, transport = 'tcp' }) {
    const existing = await this.getTrialRedemption(userId);
    if (existing && (existing.status === 'claimed' || existing.status === 'delivered')) {
      return [false, existing];
    }
    const now = nowTs();
    await this.executeTurso(
      `INSERT INTO trial_redemptions (user_id, chat_id, status, transport, created_at, updated_at, meta_json)
       VALUES (?, ?, 'claimed', ?, ?, ?, '{}')
       ON CONFLICT(user_id) DO UPDATE SET
         chat_id = excluded.chat_id,
         status = 'claimed',
         transport = excluded.transport,
         updated_at = excluded.updated_at,
         meta_json = '{}'`,
      [String(userId), String(chatId), transport, now, now]
    );
    return [true, await this.getTrialRedemption(userId)];
  }

  async markTrialDelivered({ userId, profilePublicId, orderPublicId = null }) {
    const now = nowTs();
    await this.executeTurso(
      `UPDATE trial_redemptions
       SET status = 'delivered', profile_public_id = ?, order_public_id = ?, updated_at = ?, delivered_at = ?
       WHERE user_id = ?`,
      [String(profilePublicId), orderPublicId ? String(orderPublicId) : null, now, now, String(userId)]
    );
  }

  async markTrialFailed({ userId, error }) {
    await this.executeTurso(
      `UPDATE trial_redemptions
       SET status = 'failed', updated_at = ?, meta_json = ?
       WHERE user_id = ?`,
      [nowTs(), { error: String(error || '').slice(0, 500) }, String(userId)]
    );
  }

  // --- Реферальная система (Turso) ---
  async getReferrerByUser(userId) {
    return await this.getTurso(
      `SELECT * FROM referrers WHERE user_id = ? LIMIT 1`,
      [String(userId)]
    );
  }

  async ensureReferrer({ userId, chatId, commissionPercent = 10 }) {
    const existing = await this.getReferrerByUser(userId);
    const now = nowTs();
    if (existing) {
      await this.executeTurso(
        `UPDATE referrers SET chat_id = ?, updated_at = ? WHERE user_id = ?`,
        [String(chatId), now, String(userId)]
      );
      return await this.getReferrerByUser(userId);
    }
    const code = publicId('ref', 8);
    await this.executeTurso(
      `INSERT INTO referrers (user_id, chat_id, code, commission_percent, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'active', ?, ?)`,
      [String(userId), String(chatId), code, Number(commissionPercent), now, now]
    );
    return await this.getReferrerByUser(userId);
  }

  async getReferralAttributionForUser(userId) {
    const row = await this.getTurso(
      `SELECT a.*, r.code AS referrer_code, r.user_id AS referrer_user_id, r.chat_id AS referrer_chat_id, r.commission_percent
       FROM referral_attributions a
       INNER JOIN referrers r ON r.id = a.referrer_id
       WHERE a.referred_user_id = ?
       LIMIT 1`,
      [String(userId)]
    );
    return row || null;
  }

  async countDeliveredPaidOrders({ customerChatId = null, customerEmail = null } = {}) {
    if (customerChatId != null) {
      const row = await this.getTurso(
        `SELECT count(*) as count FROM orders WHERE final_price_rub > 0 AND status = 'delivered' AND customer_chat_id = ?`,
        [String(customerChatId)]
      );
      return Number(row?.count || 0);
    }
    if (customerEmail) {
      const row = await this.getTurso(
        `SELECT count(*) as count FROM orders WHERE final_price_rub > 0 AND status = 'delivered' AND lower(customer_email) = ?`,
        [String(customerEmail).trim().toLowerCase()]
      );
      return Number(row?.count || 0);
    }
    return 0;
  }

  async attachReferral({ code, referredUserId, referredChatId }) {
    const ref = await this.getTurso(
      `SELECT * FROM referrers WHERE code = ? AND status = 'active' LIMIT 1`,
      [String(code)]
    );
    if (!ref) return ['not_found', null];
    if (String(ref.user_id) === String(referredUserId)) {
      return ['self', { id: ref.id, user_id: ref.user_id, chat_id: ref.chat_id, code: ref.code }];
    }
    const priorOrder = await this.getTurso(
      `SELECT id FROM orders WHERE customer_chat_id = ? AND final_price_rub > 0 AND status IN ('delivered', 'waiting_payment') LIMIT 1`,
      [String(referredUserId)]
    );
    if (priorOrder) return ['already_customer', null];

    const existing = await this.getReferralAttributionForUser(referredUserId);
    if (existing) return ['exists', existing];

    await this.executeTurso(
      `INSERT INTO referral_attributions (referrer_id, referred_user_id, referred_chat_id, source_code, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [ref.id, String(referredUserId), String(referredChatId), String(code), nowTs()]
    );
    return ['created', await this.getReferralAttributionForUser(referredUserId)];
  }

  async listReferralBalances() {
    const rows = await this.queryTurso(
      `SELECT r.*, u.username, u.first_name, u.last_name,
         COALESCE((SELECT SUM(l.amount_rub) FROM referral_ledger l WHERE l.referrer_id = r.id), 0) AS total_earned_rub,
         COALESCE((SELECT SUM(p.amount_rub) FROM referral_payouts p WHERE p.referrer_id = r.id), 0) AS total_paid_rub,
         (SELECT COUNT(*) FROM referral_attributions a WHERE a.referrer_id = r.id) AS referred_count,
         (SELECT COUNT(*) FROM referral_ledger l WHERE l.referrer_id = r.id) AS pending_count
       FROM referrers r
       LEFT JOIN telegram_users u ON u.user_id = r.user_id
       ORDER BY r.created_at ASC`
    );
    const results = rows.map((r) => {
      const totalEarned = Number(r.total_earned_rub || 0);
      const totalPaid = Number(r.total_paid_rub || 0);
      const balanceRub = Math.max(totalEarned - totalPaid, 0);
      return {
        id: r.id,
        user_id: r.user_id,
        chat_id: r.chat_id,
        code: r.code,
        commission_percent: Number(r.commission_percent || 10),
        status: r.status,
        username: r.username || null,
        first_name: r.first_name || null,
        last_name: r.last_name || null,
        total_earned_rub: totalEarned,
        total_paid_rub: totalPaid,
        balance_rub: balanceRub,
        pending_count: Number(r.pending_count || 0),
        referred_count: Number(r.referred_count || 0),
      };
    });
    results.sort((a, b) => b.balance_rub - a.balance_rub || a.id - b.id);
    return results;
  }

  async getReferralBalance(referrerId) {
    const list = await this.listReferralBalances();
    return list.find((item) => Number(item.id) === Number(referrerId)) || null;
  }

  async createReferralLedgerForOrder(order) {
    const finalPrice = Number(order.final_price_rub || 0);
    const kind = String(order.kind || '');
    const meta = order.meta_json || {};
    if (finalPrice <= 0 || !['purchase', 'renewal'].includes(kind)) {
      return [null, 0, 0];
    }
    if (meta.source === 'trial') return [null, 0, 0];

    let referrerId = null;
    let commissionPercent = 10;
    let attribution = null;

    if (order.customer_chat_id) {
      attribution = await this.getReferralAttributionForUser(order.customer_chat_id);
      if (attribution) {
        referrerId = Number(attribution.referrer_id);
        commissionPercent = Number(attribution.commission_percent || 10);
      }
    }
    if (!referrerId && meta.referrer_id) {
      const refRow = await this.getTurso(
        `SELECT * FROM referrers WHERE id = ? AND status = 'active' LIMIT 1`,
        [Number(meta.referrer_id)]
      );
      if (refRow) {
        referrerId = refRow.id;
        commissionPercent = refRow.commission_percent || 10;
      }
    }
    if (!referrerId) return [null, 0, 0];

    const amount = Math.max(Math.floor((finalPrice * commissionPercent) / 100), 0);
    if (amount <= 0) return [null, 0, 0];

    const balInfo = await this.getReferralBalance(referrerId);
    const oldBalance = Number(balInfo?.balance_rub || 0);

    const existingLedger = await this.getTurso(
      `SELECT * FROM referral_ledger WHERE order_public_id = ? LIMIT 1`,
      [String(order.public_id)]
    );
    if (existingLedger) {
      return [
        {
          id: existingLedger.id,
          referrer_id: existingLedger.referrer_id,
          referred_user_id: existingLedger.referred_user_id,
          order_public_id: existingLedger.order_public_id,
          base_amount_rub: existingLedger.base_amount_rub,
          amount_rub: existingLedger.amount_rub,
          commission_percent: existingLedger.commission_percent,
        },
        oldBalance,
        oldBalance,
      ];
    }

    const refUserKey = String(
      order.customer_chat_id || order.customer_email || `order_${order.public_id}`
    );
    const res = await this.executeTurso(
      `INSERT INTO referral_ledger (
        referrer_id, referred_user_id, order_public_id, base_amount_rub, amount_rub,
        commission_percent, status, created_at, meta_json
      ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
      RETURNING *`,
      [
        referrerId, refUserKey, String(order.public_id), finalPrice, amount,
        commissionPercent, nowTs(), {
          order_transport: order.transport,
          order_duration_days: order.duration_days,
          device_limit: meta.device_limit,
        }
      ]
    );
    const inserted = res.rows[0];

    if (attribution && !attribution.first_order_public_id) {
      await this.executeTurso(
        `UPDATE referral_attributions SET first_order_public_id = ? WHERE id = ?`,
        [String(order.public_id), Number(attribution.id)]
      );
    }

    return [
      {
        id: inserted.id,
        referrer_id: inserted.referrer_id,
        referred_user_id: inserted.referred_user_id,
        order_public_id: inserted.order_public_id,
        base_amount_rub: inserted.base_amount_rub,
        amount_rub: inserted.amount_rub,
        commission_percent: inserted.commission_percent,
      },
      oldBalance,
      oldBalance + amount,
    ];
  }

  async createReferralPayout({ referrerId, actor, amountRub = null }) {
    const balInfo = await this.getReferralBalance(referrerId);
    const curBalance = Number(balInfo?.balance_rub || 0);
    if (curBalance <= 0) return null;

    let payoutAmount = amountRub == null ? curBalance : Number(amountRub);
    if (payoutAmount <= 0) return null;
    if (payoutAmount > curBalance) payoutAmount = curBalance;

    const now = nowTs();
    const res = await this.executeTurso(
      `INSERT INTO referral_payouts (referrer_id, amount_rub, actor, created_at, meta_json)
       VALUES (?, ?, ?, ?, '{}')
       RETURNING *`,
      [Number(referrerId), payoutAmount, String(actor), now]
    );
    const row = res.rows[0];
    return {
      id: row.id,
      referrer_id: row.referrer_id,
      amount_rub: row.amount_rub,
      actor: row.actor,
      created_at: Number(row.created_at),
    };
  }

  // --- AWG Слоты (Turso) ---
  async listAwgSlots(profilePublicId) {
    const rows = await this.queryTurso(
      `SELECT id, profile_public_id, slot_index, slot_label, public_key, client_ip, enabled, server_code
       FROM awg_slots
       WHERE profile_public_id = ?
       ORDER BY slot_index ASC`,
      [String(profilePublicId)]
    );
    return rows.map((r) => ({
      id: r.id,
      profile_public_id: r.profile_public_id,
      slot_index: Number(r.slot_index),
      slot_label: r.slot_label,
      public_key: r.public_key,
      client_ip: r.client_ip,
      enabled: r.enabled ? 1 : 0,
      server_code: r.server_code,
    }));
  }

  async setAwgSlotEnabled(slotId, enabled) {
    await this.executeTurso(
      `UPDATE awg_slots SET enabled = ?, updated_at = ? WHERE id = ?`,
      [enabled ? 1 : 0, nowTs(), Number(slotId)]
    );
  }
}
