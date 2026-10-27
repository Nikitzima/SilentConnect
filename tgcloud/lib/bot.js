import { api, InputFile } from 'sdk';
import {
  SETTINGS,
  ACTION_GUARD_KEY,
  ACTION_GUARD_TTL_SECONDS,
  WAITING_PAYMENT_EXPIRY_SECONDS,
  ORDER_NOTIFICATION_BUMP_SECONDS,
  PAYMENT_REPORT_REPEAT_SECONDS,
  TRIAL_TRANSPORT,
  REFERRAL_COMMISSION_PERCENT,
  REFERRAL_INVITEE_DISCOUNT_PERCENT,
  REFERRAL_PAYOUT_MIN_RUB,
  PUBLIC_ACCESS_START_CODE,
  PUBLIC_MENU_DROP_KEYS,
  TEST_PROFILE_NOTES,
  ADMIN_PROFILE_NOTES,
  PUBLIC_TRIAL_PROFILE_NOTES,
} from './config.js';
import { buildOffers, quotePrice } from './catalog.js';
import { PlategaClient } from './platega.js';
import { Provisioner } from './provisioner.js';
import { daysFromNow, normalizeUsername, nowTs } from './security.js';
import { OrderStateError, Store } from './store.js';

export function kb(rows) {
  function buildButton(spec) {
    if (spec && typeof spec === 'object' && !Array.isArray(spec)) {
      const btn = { text: String(spec.text) };
      if (spec.style) btn.style = spec.style;
      if (spec.copy_text != null) {
        btn.copy_text = { text: String(spec.copy_text) };
        return btn;
      }
      const data = String(spec.data || spec.url || spec.callback_data || '');
      if (/^(https?:\/\/|tg:\/\/)/.test(data)) {
        btn.url = data;
      } else {
        btn.callback_data = data;
      }
      return btn;
    }
    const [text, data, style] = spec;
    const btn = { text: String(text) };
    if (style) btn.style = style;
    const strData = String(data || '');
    if (/^(https?:\/\/|tg:\/\/)/.test(strData)) {
      btn.url = strData;
    } else {
      btn.callback_data = strData;
    }
    return btn;
  }

  return {
    inline_keyboard: rows.map((row) => row.map(buildButton)),
  };
}

export class ShopBot {
  constructor(settings = SETTINGS) {
    this.settings = settings;
    this.store = new Store();
    this.provisioner = new Provisioner(settings, this.store);
    this.offers = buildOffers(settings);
    this.platega = new PlategaClient(settings);
  }

  // --- Обёртки над sdk/api ---
  async sendMessage(
    chatId,
    text,
    { replyMarkup = null, protectContent = false, disableWebPagePreview = true } = {}
  ) {
    const payload = {
      chat_id: chatId,
      text: String(text),
      protect_content: Boolean(protectContent),
      link_preview_options: { is_disabled: Boolean(disableWebPagePreview) },
    };
    if (replyMarkup) payload.reply_markup = replyMarkup;
    return await api.sendMessage(payload);
  }

  async editMessageText({ chatId, messageId, text, replyMarkup = null }) {
    const payload = {
      chat_id: chatId,
      message_id: Number(messageId),
      text: String(text),
      link_preview_options: { is_disabled: true },
    };
    if (replyMarkup) payload.reply_markup = replyMarkup;
    return await api.editMessageText(payload);
  }

  async deleteMessage(chatId, messageId) {
    return await api.deleteMessage({
      chat_id: chatId,
      message_id: Number(messageId),
    });
  }

  async answerCallbackQuery(callbackQueryId, text = '', showAlert = false) {
    const payload = { callback_query_id: callbackQueryId, show_alert: Boolean(showAlert) };
    if (text) payload.text = String(text);
    try {
      return await api.answerCallbackQuery(payload);
    } catch (e) {
      console.warn('api.answerCallbackQuery warning:', e?.message || e);
      return null;
    }
  }

  async _renderOrEdit(
    chatId,
    text,
    {
      replyMarkup = null,
      messageId = null,
      protectContent = false,
      disableWebPagePreview = true,
    } = {}
  ) {
    if (messageId != null) {
      try {
        return await this.editMessageText({
          chatId,
          messageId: Number(messageId),
          text,
          replyMarkup,
        });
      } catch (err) {
        if (String(err?.description || err?.message || '').toLowerCase().includes('message is not modified')) {
          return { message_id: Number(messageId) };
        }
        try {
          await this.deleteMessage(chatId, Number(messageId));
        } catch (_) {
          // ignore
        }
      }
    }
    return await this.sendMessage(chatId, text, {
      replyMarkup,
      protectContent,
      disableWebPagePreview,
    });
  }

  // --- Ссылки и форматирование ---
  inviteLink(inviteCode) {
    return `https://t.me/${this.settings.telegramBotUsername}?start=${inviteCode}`;
  }

  referralLink(referralCode) {
    return `https://t.me/${this.settings.telegramBotUsername}?start=${referralCode}`;
  }

  webReferralLink(referralCode) {
    const base = String(this.settings.webPublicBaseUrl || '').replace(/\/+$/, '');
    return `${base || 'https://shop.example.com'}/?ref=${referralCode}`;
  }

  publicAccessLink() {
    return `https://t.me/${this.settings.telegramBotUsername}?start=${PUBLIC_ACCESS_START_CODE}`;
  }

  legalTermsUrl() {
    const base = String(this.settings.webPublicBaseUrl || 'https://shop.example.com').replace(/\/+$/, '');
    return `${base}/legal/terms`;
  }

  legalPrivacyUrl() {
    const base = String(this.settings.webPublicBaseUrl || 'https://shop.example.com').replace(/\/+$/, '');
    return `${base}/legal/privacy`;
  }

  legalRefundUrl() {
    const base = String(this.settings.webPublicBaseUrl || 'https://shop.example.com').replace(/\/+$/, '');
    return `${base}/legal/refund`;
  }

  _supportContact() {
    const raw = String(this.settings.supportTgUrl || '').trim();
    if (!raw) return '@SilentConnectHelp';
    if (raw.startsWith('@')) return raw;
    if (raw.startsWith('https://t.me/')) {
      const handle = raw.slice('https://t.me/'.length).replace(/^\/+|\/+$/g, '');
      if (handle) return `@${handle}`;
    }
    return raw;
  }

  static transportLabel(transport) {
    if (transport === 'xhttp') return 'XHTTP';
    if (transport === 'tcp') return 'Стандартный';
    if (transport === 'hybrid') return 'Универсальный';
    return String(transport);
  }

  static formatTs(value) {
    const ts = Number(value || 0);
    if (!ts || ts <= 0) return 'не указано';
    const d = new Date(ts * 1000);
    const dd = String(d.getUTCDate()).padStart(2, '0');
    const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
    const yyyy = d.getUTCFullYear();
    const hh = String(d.getUTCHours()).padStart(2, '0');
    const min = String(d.getUTCMinutes()).padStart(2, '0');
    return `${dd}.${mm}.${yyyy} ${hh}:${min}`;
  }

  static deviceLimitLabel(deviceLimit) {
    const limit = Number(deviceLimit || 0);
    if (limit <= 0) return 'без лимита';
    return `до ${limit} устройств одновременно`;
  }

  static formatGb(value) {
    const raw = Number(value || 0);
    return `${(raw / 1024 ** 3).toFixed(2)} GB`;
  }

  static formatXuiTs(value) {
    let ts = Number(value || 0);
    if (ts > 1e12) ts = Math.floor(ts / 1000);
    return ShopBot.formatTs(ts);
  }

  static _subscriptionIdFromUrl(subscriptionUrl) {
    try {
      const u = new URL(subscriptionUrl);
      const parts = u.pathname.replace(/\/+$/, '').split('/');
      return decodeURIComponent(parts[parts.length - 1] || '');
    } catch (_) {
      return '';
    }
  }

  static _subscriptionSetupUrl(subscriptionUrl) {
    try {
      const u = new URL(subscriptionUrl);
      const parts = u.pathname.split('/').filter(Boolean);
      const subId = parts[parts.length - 1] || '';
      if (parts.length >= 3) {
        const baseParts = parts.slice(0, -2);
        u.pathname = '/' + [...baseParts, 'import', subId].join('/');
      } else {
        u.pathname = `/import/${subId}`;
      }
      u.search = '';
      u.hash = '';
      return u.toString();
    } catch (_) {
      return subscriptionUrl;
    }
  }

  _subscriptionUrlFromId(subscriptionId) {
    return `${this.settings.subscriptionBaseUrl}/${encodeURIComponent(subscriptionId)}`;
  }

  _hybridSubscriptionUrl(tcpSubId, xhttpSubId) {
    try {
      const u = new URL(this.settings.subscriptionBaseUrl);
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length) parts.pop();
      u.pathname = '/' + [...parts, 'json-hybrid', `${tcpSubId}~${xhttpSubId}`].join('/');
      return u.toString();
    } catch (_) {
      return `${this.settings.subscriptionBaseUrl}-hybrid/${tcpSubId}~${xhttpSubId}`;
    }
  }

  isAdmin(userOrId) {
    if (userOrId == null) return false;
    const rawId = typeof userOrId === 'object' ? (userOrId.id ?? userOrId.user_id) : userOrId;
    const numId = Number(rawId);
    if (Number.isFinite(numId) && (this.settings.adminUserIds || []).includes(numId)) {
      return true;
    }
    if (typeof userOrId === 'object' && userOrId.username) {
      const uname = normalizeUsername(userOrId.username);
      if (uname && (this.settings.adminUsernames || []).includes(uname)) {
        return true;
      }
    }
    return false;
  }

  // --- Сессии и Action Guard ---
  static _contextFromSession(session) {
    return { ...(session?.context_json || {}) };
  }

  async _setSessionState(chatId, scope, state, context = {}) {
    const payload = { ...context };
    await this.store.setSession(chatId, scope, state, payload);
    return payload;
  }

  async _mergeSessionState(chatId, scope, state, updates = null, { dropKeys = [] } = {}) {
    const session = await this.store.getSession(chatId);
    const context = ShopBot._contextFromSession(session);
    for (const key of dropKeys) {
      delete context[key];
    }
    if (updates) Object.assign(context, updates);
    await this.store.setSession(chatId, scope, state, context);
    return context;
  }

  static _getActionGuard(context) {
    const g = context?.[ACTION_GUARD_KEY];
    return g && typeof g === 'object' ? g : null;
  }

  static _matchingActionGuard(context, actionKey) {
    const g = ShopBot._getActionGuard(context);
    return g && g.action_key === actionKey ? g : null;
  }

  static _actionGuardStale(guard) {
    const startedAt = Number(guard?.started_at || 0);
    return startedAt > 0 && nowTs() - startedAt >= ACTION_GUARD_TTL_SECONDS;
  }

  async _claimAction(chatId, { scope, state, actionKey, context }) {
    const guard = ShopBot._matchingActionGuard(context, actionKey);
    if (guard && guard.status === 'in_flight' && !ShopBot._actionGuardStale(guard)) {
      return [false, guard];
    }
    context[ACTION_GUARD_KEY] = {
      action_key: actionKey,
      status: 'in_flight',
      started_at: nowTs(),
    };
    await this.store.setSession(chatId, scope, state, context);
    return [true, context[ACTION_GUARD_KEY]];
  }

  async _completeAction(chatId, { scope, state, context, actionKey, resultKind, ...fields }) {
    let startedAt = nowTs();
    const existing = ShopBot._matchingActionGuard(context, actionKey);
    if (existing && Number(existing.started_at || 0) > 0) {
      startedAt = Number(existing.started_at);
    }
    const guard = {
      action_key: actionKey,
      status: 'completed',
      started_at: startedAt,
      completed_at: nowTs(),
      result_kind: resultKind,
      ...fields,
    };
    context[ACTION_GUARD_KEY] = guard;
    await this.store.setSession(chatId, scope, state, context);
    return guard;
  }

  async _clearActionIfMatches(chatId, actionKey, { statuses = ['in_flight'] } = {}) {
    const session = await this.store.getSession(chatId);
    if (!session) return;
    const context = ShopBot._contextFromSession(session);
    const guard = ShopBot._matchingActionGuard(context, actionKey);
    if (!guard) return;
    if (statuses && !statuses.includes(String(guard.status || ''))) return;
    delete context[ACTION_GUARD_KEY];
    await this.store.setSession(chatId, session.scope, session.state, context);
  }

  async _notifyActionInFlight(chatId) {
    await this.sendMessage(chatId, 'Уже обрабатывается. Новый дубль не создаю.');
  }

  // --- Цены и Промокоды ---
  orderDeviceLimit(order) {
    const meta = order?.meta_json || {};
    if (meta.device_limit != null) return Number(meta.device_limit);
    return Number(this.settings.defaultDeviceLimit);
  }

  promoDeviceLimit(promo) {
    if (promo?.device_limit != null) return Number(promo.device_limit);
    return Number(this.settings.defaultDeviceLimit);
  }

  static promoType(promo) {
    return String(promo?.promo_type || 'fixed');
  }

  static promoDurationLabel(promo) {
    const months = promo?.duration_months;
    if (months) {
      return `${Number(months)} мес. (${Number(promo.duration_days || 0)} дн.)`;
    }
    const days = Number(promo?.duration_days || 0);
    if (days === 36500) return 'пожизненно';
    return `${days} дн.`;
  }

  static fixedPromoFinalPrice(promo, basePrice) {
    if (promo?.fixed_price_rub != null) {
      return Math.max(Number(promo.fixed_price_rub), 0);
    }
    return Math.max(
      Math.floor((Number(basePrice) * (100 - Number(promo.discount_percent || 0))) / 100),
      0
    );
  }

  static fixedPromoPriceLabel(promo, basePrice = null) {
    if (promo?.fixed_price_rub != null) {
      return `${Number(promo.fixed_price_rub)} RUB`;
    }
    const discount = Number(promo?.discount_percent || 0);
    if (discount) return `скидка ${discount}%`;
    if (basePrice == null) return 'обычная цена';
    return `обычная цена (${Number(basePrice)} RUB)`;
  }

  basePriceForDuration(transport, durationDays, { deviceLimit = null } = {}) {
    const limit = Number(deviceLimit == null ? this.settings.defaultDeviceLimit : deviceLimit);
    return quotePrice(limit, Number(durationDays), this.settings);
  }

  async _activeDiscountPromoFromContext(context) {
    const promoId = context?.discount_promo_id;
    if (!promoId) return null;
    const promo = await this.store.getValidPromoById(Number(promoId));
    if (promo && ShopBot.promoType(promo) === 'discount') return promo;
    return null;
  }

  async _publicHasPurchaseAccess(chatId, context = null) {
    if (!this.settings.inviteRequired) return true;
    const payload = { ...(context || {}) };
    if (payload.invite_id || payload.referrer_id || payload.public_access) return true;
    if (payload.discount_promo_id && (await this._activeDiscountPromoFromContext(payload))) {
      return true;
    }
    const session = await this.store.getSession(chatId);
    if (session && session.scope === 'public') {
      const sc = ShopBot._contextFromSession(session);
      if (sc.invite_id || sc.referrer_id || sc.public_access) return true;
      if (sc.discount_promo_id && (await this._activeDiscountPromoFromContext(sc))) {
        return true;
      }
    }
    if (await this.store.getReferralAttributionForUser(chatId)) return true;
    return (await this.store.getLatestOrderForChat(chatId)) != null;
  }

  // --- Platega и ожидания оплаты ---
  async getOrCreatePlategaPaymentUrl(order) {
    if (!this.settings.plategaEnabled || !this.platega.isConfigured) return '';
    const meta = { ...(order.meta_json || {}) };
    const existingUrl = String(meta.platega_url || '').trim();
    if (existingUrl) return existingUrl;

    try {
      const amount = Number(order.final_price_rub || 0);
      if (amount <= 0) return '';
      const duration = Number(order.duration_days || 30);
      const desc = `SilentConnect #${order.public_id} (${duration} дн.)`;
      const tx = await this.platega.createTransaction({
        amount,
        currency: 'RUB',
        description: desc,
        payload: String(order.public_id),
        metadata: {
          order_id: String(order.public_id),
          chat_id: String(order.customer_chat_id || ''),
        },
        isBot: true,
      });
      const url = String(tx.url || '').trim();
      const txId = String(tx.transactionId || '').trim();
      if (url) {
        meta.platega_url = url;
        if (txId) meta.platega_transaction_id = txId;
        await this.store.updateOrderMeta(String(order.public_id), meta);
        order.meta_json = meta;
        return url;
      }
    } catch (err) {
      console.error(`Failed to create Platega URL for order ${order.public_id}:`, err);
    }
    return '';
  }

  async _publicWaitingPaymentMarkup(orderPublicId, order = null) {
    const supportUrl = String(this.settings.supportTgUrl || '').trim() || 'https://t.me/SilentConnectHelp';
    const ord = order || (await this.store.getOrder(orderPublicId));
    let plategaUrl = '';
    if (ord && this.settings.plategaEnabled) {
      plategaUrl = await this.getOrCreatePlategaPaymentUrl(ord);
    }

    const rows = [];
    if (plategaUrl) {
      rows.push([['💳 Оплатить онлайн (СБП / Карты / Крипта)', plategaUrl]]);
      rows.push([['🔄 Проверить зачисление', `public:check_payment:${orderPublicId}`, 'primary']]);
      rows.push([['Отменить заказ', `public:cancel_waiting:${orderPublicId}`, 'danger']]);
      rows.push([['У меня есть промокод', `public:promo_switch:${orderPublicId}`]]);
      rows.push([['💬 Написать в поддержку', supportUrl]]);
    } else {
      rows.push([['💬 Написать оператору для оплаты', supportUrl]]);
      rows.push([['Оплачено', `public:payment_sent:${orderPublicId}`, 'success']]);
      rows.push([['Отменить заказ', `public:cancel_waiting:${orderPublicId}`, 'danger']]);
      rows.push([['У меня есть промокод', `public:promo_switch:${orderPublicId}`]]);
    }
    return kb(rows);
  }

  async _waitingPaymentMessage(order, { prefix = null } = {}) {
    const lines = [];
    if (prefix) lines.push(prefix);
    lines.push(`Заказ \`${order.public_id}\` уже создан.`);
    const meta = order.meta_json || {};
    if (order.kind === 'renewal') {
      lines.push(
        meta.upgrade_only
          ? 'Тип: увеличение лимита текущей подписки.'
          : 'Тип: продление текущей подписки.'
      );
    }
    if (!order.promo_id || meta.promo_type === 'discount') {
      lines.push(`Транспорт: ${ShopBot.transportLabel(String(order.transport))}`);
      if (meta.upgrade_only) {
        lines.push('Срок: без продления, до текущей даты окончания.');
      } else {
        lines.push(`Срок: ${Number(order.duration_days)} дн.`);
      }
    }
    if (order.promo_id && meta.promo_type === 'discount') {
      lines.push(
        `Скидка по промокоду: ${Number(order.base_price_rub)} -> ${Number(order.final_price_rub)} RUB.`
      );
    }
    const deviceLimit = this.orderDeviceLimit(order);
    lines.push(`Лимит: ${ShopBot.deviceLimitLabel(deviceLimit)}.`);
    lines.push(`Сумма к оплате: ${Number(order.final_price_rub)} RUB.`);

    let plategaUrl = String(meta.platega_url || '').trim();
    if (!plategaUrl && this.settings.plategaEnabled) {
      plategaUrl = await this.getOrCreatePlategaPaymentUrl(order);
    }

    if (plategaUrl) {
      lines.push(
        '',
        'Для быстрой оплаты нажмите кнопку «💳 Оплатить онлайн» ниже.',
        'Поддерживаются СБП, банковские карты РФ и криптовалюта.',
        '',
        '💡 Комиссия шлюза оплачивается покупателем. Для прямой оплаты без комиссии обратитесь к менеджеру через кнопку «💬 Написать в поддержку».',
        '',
        'После подтверждения оплаты доступ будет выдан автоматически!'
      );
    } else {
      lines.push(
        '',
        'Для оплаты нажмите кнопку «💬 Написать оператору для оплаты» и отправьте менеджеру номер заказа.',
        `Номер заказа: \`${order.public_id}\`.`,
        '',
        '💡 Комиссия шлюза оплачивается покупателем. Для прямой оплаты без комиссии обратитесь к менеджеру через кнопку «💬 Написать в поддержку».',
        '',
        'После оплаты нажмите «Оплачено». Мы подтвердим заказ и бот сразу пришлёт ссылку доступа.'
      );
    }
    return lines.join('\n');
  }

  // --- Главное меню и витрина ---
  async _publicHomeText({ prefix = null, activeProfile = null } = {}) {
    const lines = [];
    if (prefix) lines.push(prefix, '');
    if (activeProfile && Number(activeProfile.expires_at || 0) > nowTs()) {
      const expiresStr = ShopBot.formatTs(activeProfile.expires_at);
      const limit = await this._profileDeviceLimit(activeProfile);
      lines.push(
        `🐍 ${this.settings.brandName}`,
        '',
        'Главное меню',
        '',
        `✅ Ваша подписка активна до: ${expiresStr}`,
        `Лимит устройств: ${ShopBot.deviceLimitLabel(limit)}`,
        '',
        'Выберите действие с помощью кнопок ниже:',
        '',
        '• Личный кабинет (ссылка доступа и подключение)',
        '• Продлить подписку или изменить тариф',
        '• Инструкции по настройке и поддержка',
        '',
        '[code: mekbuda]'
      );
    } else {
      lines.push(
        `🐍 ${this.settings.brandName}`,
        '',
        'Главное меню',
        '',
        'Выберите действие с помощью кнопок ниже:',
        '',
        '• Оформить быстрый приватный доступ к интернету',
        '• Продлить подписку или активировать пробный период',
        '• Ввести промокод или пригласить друзей',
        '• Инструкции по настройке и поддержка',
        '',
        '[code: mekbuda]'
      );
    }
    return lines.join('\n');
  }

  _publicHomeMarkup({ activeProfile = null } = {}) {
    const rows = [];
    if (activeProfile && Number(activeProfile.expires_at || 0) > nowTs()) {
      rows.push([['👤 Личный кабинет', 'public:cabinet', 'success']]);
      rows.push([
        ['🔄 Продлить подписку', 'public:renew', 'success'],
        ['🚀 Выбрать тариф', 'public:access', 'primary'],
      ]);
    } else {
      rows.push([['🚀 Подключить доступ / Выбрать тариф', 'public:access', 'success']]);
      rows.push([
        ['🔄 Продлить подписку', 'public:renew', 'success'],
        ['🎁 Пробный период', 'public:trial', 'success'],
      ]);
    }
    rows.push(
      [
        ['🎟 Промокод', 'public:promo'],
        ['🤝 Рефералы', 'public:referral', 'success'],
      ],
      [
        ['📖 Помощь & FAQ', 'public:help', 'primary'],
        ['💬 Поддержка', 'public:support', 'primary'],
      ]
    );
    return kb(rows);
  }

  _publicAccessMarkup() {
    const price3 = this.offers['tcp_3_30'].priceRub;
    const price6 = this.offers['tcp_6_30'].priceRub;
    const price9 = this.offers['tcp_9_30'].priceRub;
    return kb([
      [[`Личный • 3 устройства • 30 дней • ${price3} RUB`, 'public:buy:tcp_3_30', 'success']],
      [[`Домашний • 6 устройств • 30 дней • ${price6} RUB`, 'public:buy:tcp_6_30', 'success']],
      [[`Расширенный • 9 устройств • 30 дней • ${price9} RUB`, 'public:buy:tcp_9_30', 'success']],
      [['🎁 Бесплатная неделя', 'public:trial', 'primary']],
      [['Назад в меню', 'public:menu']],
    ]);
  }

  static _durationLabel(durationDays) {
    const d = Number(durationDays);
    if (d === 30) return '1 месяц';
    if (d === 90) return '3 месяца';
    if (d === 180) return '6 месяцев';
    if (d === 360) return '12 месяцев';
    return `${d} дн.`;
  }

  static _devicePlanTitle(deviceLimit) {
    const l = Number(deviceLimit);
    if (l <= 3) return 'Личный';
    if (l <= 6) return 'Домашний';
    return 'Расширенный';
  }

  _purchaseOfferCode(context) {
    const deviceLimit = Number(context.buy_device_limit || 3);
    const durationDays = Number(context.buy_duration_days || 30);
    const mode = String(context.buy_mode || 'tcp');
    return `${mode}_${deviceLimit}_${durationDays}`;
  }

  async _expireStaleWaitingOrders(chatId, { notifyUser = true } = {}) {
    const expiredOrders = await this.store.expireWaitingPaymentOrdersForChat(chatId, {
      olderThanSeconds: WAITING_PAYMENT_EXPIRY_SECONDS,
    });
    if (!expiredOrders.length) return [];

    const session = await this.store.getSession(chatId);
    if (session && session.scope === 'public') {
      const context = ShopBot._contextFromSession(session);
      const expiredIds = new Set(expiredOrders.map((o) => String(o.public_id)));
      if (expiredIds.has(String(context.order_public_id || '')) || session.state === 'waiting_payment') {
        delete context[ACTION_GUARD_KEY];
        delete context.order_public_id;
        delete context.pending_promo;
        delete context.pending_promo_id;
        await this.store.setSession(chatId, 'public', 'menu', context);
      }
    }

    if (notifyUser) {
      await this.sendMessage(
        chatId,
        'Старый неоплаченный заказ истёк через 6 часов и больше не мешает. Можно начать заново.'
      );
    }
    return expiredOrders;
  }

  async _freshActiveOrderForChat(chatId, { notifyUser = true } = {}) {
    await this._expireStaleWaitingOrders(chatId, { notifyUser });
    return await this.store.getActiveOrderForChat(chatId);
  }

  async _latestRenewableProfileForUser(user, chatId) {
    const userId = user?.id || chatId;
    const profile = await this.store.getLatestRenewableProfileForUser(userId, {
      excludedNotes: [TEST_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES],
    });
    if (!profile) return null;
    const found = await this.provisioner.findClientByEmail(String(profile.xui_email));
    if (!found) {
      await this.store.markProfileDeleted(String(profile.public_id));
      return null;
    }
    return profile;
  }

  async _profileDeviceLimit(profile) {
    const found = await this.provisioner.findClientByEmail(String(profile.xui_email));
    if (!found) return Number(this.settings.defaultDeviceLimit);
    const limit = Number(found.client?.limitIp || profile.device_limit || 0);
    return limit > 0 ? limit : Number(this.settings.defaultDeviceLimit);
  }

  async _activeProfileForChat(chatId, user = null) {
    const effUser = user || { id: chatId };
    const profile = await this._latestRenewableProfileForUser(effUser, chatId);
    if (profile && Number(profile.expires_at || 0) > nowTs()) {
      return profile;
    }
    return null;
  }

  async showPublicMenu(
    chatId,
    message = null,
    { dropKeys = PUBLIC_MENU_DROP_KEYS, messageId = null, user = null } = {}
  ) {
    await this._expireStaleWaitingOrders(chatId, { notifyUser: true });
    await this._mergeSessionState(chatId, 'public', 'menu', null, { dropKeys });
    const activeProfile = await this._activeProfileForChat(chatId, user);
    const text = await this._publicHomeText({ prefix: message, activeProfile });
    await this._renderOrEdit(chatId, text, {
      replyMarkup: this._publicHomeMarkup({ activeProfile }),
      messageId,
    });
  }

  async _sendPublicSubscription(chatId, subscriptionUrl, { prefix }) {
    const setupUrl = ShopBot._subscriptionSetupUrl(subscriptionUrl);
    await this.sendMessage(
      chatId,
      `${prefix}\n${subscriptionUrl}\n\n` +
        'Не теряйте её: это персональный ключ доступа. Пока профиль не удалён, продлить подписку можно кнопкой в боте.\n\n' +
        'Нажмите «Подключить»: страница сама предложит систему, подходящие приложения и запасной способ через копирование.',
      {
        replyMarkup: kb([
          [['Подключить', setupUrl, 'success']],
          [{ text: 'Скопировать ссылку', copy_text: subscriptionUrl, style: 'primary' }],
          [
            ['Как подключить', 'public:help', 'primary'],
            ['Назад в меню', 'public:menu'],
          ],
        ]),
        protectContent: true,
      }
    );
  }

  async _recoverSubscriptionForProfile(profilePublicId) {
    const profile = await this.store.getProfile(profilePublicId);
    if (!profile) throw new Error(`Profile ${profilePublicId} is absent in store`);
    const found = await this.provisioner.findClientByEmail(String(profile.xui_email));
    if (!found) throw new Error(`Profile ${profilePublicId} is absent in x-ui`);
    const subId = String(found.client?.subId || profile.xui_client_id || '');
    if (!subId) throw new Error(`Profile ${profilePublicId} has no subId`);
    return {
      profile,
      subscription_url: `${this.settings.subscriptionBaseUrl}/${subId}`,
      sub_id: subId,
    };
  }

  async _recoverSubscriptionForOrder(order) {
    const meta = order.meta_json || {};
    if (meta.hybrid && meta.tcp_profile_public_id && meta.xhttp_profile_public_id) {
      const tcpRes = await this._recoverSubscriptionForProfile(String(meta.tcp_profile_public_id));
      const xhttpRes = await this._recoverSubscriptionForProfile(String(meta.xhttp_profile_public_id));
      return {
        profile: tcpRes.profile,
        subscription_url: this._hybridSubscriptionUrl(String(tcpRes.sub_id), String(xhttpRes.sub_id)),
        sub_id: `${tcpRes.sub_id}~${xhttpRes.sub_id}`,
      };
    }
    const profile = await this.store.getProfileForOrder(order.public_id);
    if (!profile) throw new Error(`Order ${order.public_id} has no linked profile`);
    return await this._recoverSubscriptionForProfile(profile.public_id);
  }

  async _sendExistingPublicOrder(chatId, order, { prefix, bumpAdmin = true } = {}) {
    if (order.status === 'waiting_payment') {
      await this._mergeSessionState(chatId, 'public', 'waiting_payment', {
        order_public_id: order.public_id,
      });
      const msg = await this._waitingPaymentMessage(order, { prefix });
      const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
      await this.sendMessage(chatId, msg, { replyMarkup: markup });
      if (bumpAdmin) {
        await this.notifyAdminsAboutOrder(order, { bump: true });
      }
      return;
    }
    if (order.status === 'auto_provision') {
      if (order.provisioned_profile_id) {
        const result = await this._recoverSubscriptionForOrder(order);
        await this._mergeSessionState(chatId, 'public', 'menu');
        await this._sendPublicSubscription(chatId, result.subscription_url, {
          prefix: 'Ссылка уже была создана, отправляю повторно.',
        });
        return;
      }
      await this.sendMessage(chatId, 'Уже обрабатывается. Возвращаю текущий заказ.');
      return;
    }
  }

  async showPublicCabinet(chatId, user = null, { messageId = null } = {}) {
    const effUser = user || { id: chatId };
    let profile = await this._activeProfileForChat(chatId, effUser);
    if (!profile) {
      profile = await this._latestRenewableProfileForUser(effUser, chatId);
    }
    if (!profile) {
      await this.sendMessage(chatId, 'У вас пока нет активной подписки. Выберите тариф для подключения:', {
        replyMarkup: this._publicAccessMarkup(),
      });
      return;
    }
    try {
      const owner = await this.store.getProfileOwner(String(profile.public_id));
      const orderPublicId = String(owner?.source_order_public_id || '');
      let result;
      if (orderPublicId) {
        const order = await this.store.getOrder(orderPublicId);
        if (order && order.meta_json?.hybrid) {
          result = await this._recoverSubscriptionForOrder(order);
        } else {
          result = await this._recoverSubscriptionForProfile(String(profile.public_id));
        }
      } else {
        result = await this._recoverSubscriptionForProfile(String(profile.public_id));
      }
      await this._sendPublicSubscription(chatId, result.subscription_url, {
        prefix: 'Личный кабинет',
      });
    } catch (err) {
      console.error(`Failed to recover subscription for cabinet (chatId=${chatId}):`, err);
      await this.sendMessage(
        chatId,
        'Не удалось загрузить данные подписки. Попробуйте обновить меню или обратитесь в поддержку.',
        {
          replyMarkup: kb([[['Назад в меню', 'public:menu']], [['Поддержка', 'public:support', 'primary']]]),
        }
      );
    }
  }

  // --- Витрина покупки ---
  async showPublicAccessMenu(chatId, { messageId = null } = {}) {
    await this._expireStaleWaitingOrders(chatId, { notifyUser: true });
    const context = await this._mergeSessionState(chatId, 'public', 'buy_devices', null, {
      dropKeys: ['pending_promo', 'pending_promo_id', 'buy_device_limit', 'buy_duration_days', 'buy_mode'],
    });
    if (!(await this._publicHasPurchaseAccess(chatId, context))) {
      await this._sendAccessLocked(chatId);
      return;
    }
    const activeOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
    if (activeOrder) {
      await this._sendExistingPublicOrder(chatId, activeOrder, { prefix: 'Возвращаю текущий заказ.' });
      return;
    }
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const lines = [
      '🚀 Оформление доступа',
      '',
      'Сначала выберите, сколько устройств будет подключаться одновременно.',
      'Технические настройки уже подготовлены, разбираться в них не нужно.',
    ];
    if (discountPromo) {
      lines.push('', `Активен промокод: скидка ${Number(discountPromo.discount_percent)}%.`);
    }
    await this._renderOrEdit(chatId, lines.join('\n'), {
      replyMarkup: kb([
        [['Личный · до 3 устройств', 'public:buy_devices:3', 'success']],
        [['Домашний · до 6 устройств', 'public:buy_devices:6']],
        [['Расширенный · до 9 устройств', 'public:buy_devices:9']],
        [['« Назад в меню', 'public:menu']],
      ]),
      messageId,
    });
  }

  async showPublicBuyDuration(chatId, deviceLimit, { messageId = null } = {}) {
    const session = (await this.store.getSession(chatId)) || {
      scope: 'public',
      state: 'buy_devices',
      context_json: {},
    };
    const context = ShopBot._contextFromSession(session);
    context.buy_device_limit = Number(deviceLimit);
    await this.store.setSession(chatId, 'public', 'buy_duration', context);
    await this._renderOrEdit(
      chatId,
      `${ShopBot._devicePlanTitle(deviceLimit)}: до ${deviceLimit} устройств.\n\nТеперь выберите срок доступа.`,
      {
        replyMarkup: kb([
          [
            ['1 месяц', 'public:buy_duration:30'],
            ['3 месяца', 'public:buy_duration:90'],
          ],
          [
            ['6 месяцев', 'public:buy_duration:180'],
            ['12 месяцев', 'public:buy_duration:360'],
          ],
          [['« Назад', 'public:access']],
        ]),
        messageId,
      }
    );
  }

  async showPublicBuyConfirm(chatId, mode = 'tcp', { messageId = null } = {}) {
    const session = (await this.store.getSession(chatId)) || {
      scope: 'public',
      state: 'buy_duration',
      context_json: {},
    };
    const context = ShopBot._contextFromSession(session);
    if (!context.buy_device_limit || !context.buy_duration_days) {
      await this.showPublicAccessMenu(chatId, { messageId });
      return;
    }
    context.buy_mode = 'tcp';
    await this.store.setSession(chatId, 'public', 'buy_confirm', context);
    const offer = this.offers[this._purchaseOfferCode(context)];
    if (!offer) {
      await this.sendMessage(chatId, 'Не удалось собрать тариф. Попробуйте выбрать заново.');
      await this.showPublicAccessMenu(chatId, { messageId });
      return;
    }
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const discount = discountPromo ? Number(discountPromo.discount_percent) : 0;
    const finalPrice = Math.max(Math.floor((offer.priceRub * (100 - discount)) / 100), 0);
    const priceLine = discountPromo
      ? `${offer.priceRub} -> ${finalPrice} RUB по промокоду`
      : `${finalPrice} RUB`;

    await this._renderOrEdit(
      chatId,
      [
        'Проверьте заказ',
        '',
        `Тариф: ${ShopBot._devicePlanTitle(offer.deviceLimit)}`,
        `Лимит: ${ShopBot.deviceLimitLabel(offer.deviceLimit)}`,
        `Срок: ${ShopBot._durationLabel(offer.durationDays)}`,
        `К оплате: ${priceLine}`,
        '',
        '💡 Комиссия шлюза оплачивается покупателем. Для прямой оплаты без комиссии обратитесь к менеджеру через кнопку «Поддержка».',
      ].join('\n'),
      {
        replyMarkup: kb([
          [['Перейти к оплате', 'public:buy_confirm', 'success']],
          [['Выбрать другой срок', 'public:buy_back:duration']],
          [['💬 Поддержка', this.settings.supportTgUrl || 'https://t.me/SilentConnectHelp']],
          [['« Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  // --- Продление и апгрейд ---
  async _renewalTarget(profilePublicId) {
    const profile = await this.store.getProfile(profilePublicId);
    if (!profile || profile.status === 'deleted') return null;
    const notes = String(profile.notes || '').toLowerCase();
    if (
      !notes.includes('admin_personal') &&
      !String(profile.xui_email || '').startsWith('admin-') &&
      ([TEST_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES].includes(profile.notes) ||
        notes.includes('trial') ||
        notes.includes('test') ||
        notes.includes('auto_delete'))
    ) {
      return null;
    }
    const found = await this.provisioner.findClientByEmail(String(profile.xui_email));
    if (!found) {
      await this.store.markProfileDeleted(profilePublicId);
      return null;
    }

    const owner = (await this.store.getProfileOwner(profilePublicId)) || {};
    let sourceOrderPublicId = String(owner.source_order_public_id || '');
    if (!sourceOrderPublicId) {
      const ord = await this.store.getOrderForProfile(profilePublicId);
      sourceOrderPublicId = String(ord?.public_id || '');
    }
    const sourceOrder = sourceOrderPublicId ? await this.store.getOrder(sourceOrderPublicId) : null;
    const sourceMeta = { ...(sourceOrder?.meta_json || {}) };

    const target = {
      transport: String(profile.transport),
      profile,
      renewal_profile_public_id: profilePublicId,
      renewal_xhttp_profile_public_id: '',
      source_order_public_id: sourceOrderPublicId,
      expires_at: Number(profile.expires_at || 0),
      device_limit: await this._profileDeviceLimit(profile),
      hybrid: false,
    };

    if (sourceMeta.hybrid) {
      const tcpId = String(sourceMeta.tcp_profile_public_id || sourceMeta.renewal_profile_public_id || '');
      const xhttpId = String(
        sourceMeta.xhttp_profile_public_id || sourceMeta.renewal_xhttp_profile_public_id || ''
      );
      const tcpProfile = tcpId ? await this.store.getProfile(tcpId) : null;
      const xhttpProfile = xhttpId ? await this.store.getProfile(xhttpId) : null;
      if (!tcpProfile || !xhttpProfile || tcpProfile.status === 'deleted' || xhttpProfile.status === 'deleted') {
        return null;
      }
      target.transport = 'hybrid';
      target.profile = tcpProfile;
      target.renewal_profile_public_id = tcpId;
      target.renewal_xhttp_profile_public_id = xhttpId;
      target.expires_at = Math.min(Number(tcpProfile.expires_at || 0), Number(xhttpProfile.expires_at || 0));
      target.device_limit = await this._profileDeviceLimit(tcpProfile);
      target.hybrid = true;
    }
    return target;
  }

  async _sendRenewalTargetMissing(chatId, { messageId = null } = {}) {
    await this._renderOrEdit(
      chatId,
      'Подписка не найдена или уже недоступна на сервере. Можно вставить другую ссылку или написать в поддержку.',
      {
        replyMarkup: kb([
          [['Вставить другую ссылку', 'public:renew_other', 'primary']],
          [['Поддержка', 'public:support']],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async _sendRenewalOverview(chatId, profile, { prefix = null, messageId = null } = {}) {
    const target = await this._renewalTarget(String(profile.public_id));
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const prof = target.profile;
    const context = ShopBot._contextFromSession(await this.store.getSession(chatId));
    context.renewal_profile_public_id = String(prof.public_id);
    await this.store.setSession(chatId, 'public', 'renewal_menu', context);

    const currentLimit = Number(target.device_limit);
    const active = Number(target.expires_at) > nowTs();
    const lines = [];
    if (prefix) lines.push(prefix, '');
    lines.push(
      'Найдена подписка для продления.',
      '',
      `Профиль: ${prof.xui_email}`,
      `Режим: ${ShopBot.transportLabel(String(target.transport))}`,
      `Лимит: ${ShopBot.deviceLimitLabel(currentLimit)}`,
      `Текущий срок до: ${ShopBot.formatTs(target.expires_at)}`,
      '',
      'Можно продлить на новый срок, изменить лимит устройств или вставить другую ссылку.'
    );
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    if (discountPromo) {
      lines.push(`Активен промокод: скидка ${Number(discountPromo.discount_percent)}%.`);
    }
    const rows = [[['Продлить / изменить тариф', `public:renew_devices:${prof.public_id}`, 'success']]];
    if (active && currentLimit < 9) {
      rows.push([['Увеличить лимит сейчас', `public:upgrade_devices:${prof.public_id}`, 'primary']]);
    }
    rows.push(
      [['Ввести промокод на скидку', 'public:renew_promo']],
      [['Вставить другую ссылку', 'public:renew_other']],
      [['Назад в меню', 'public:menu']]
    );
    await this._renderOrEdit(chatId, lines.join('\n'), {
      replyMarkup: kb(rows),
      messageId,
    });
  }

  async showPublicRenewal(chatId, user, { messageId = null } = {}) {
    await this._expireStaleWaitingOrders(chatId, { notifyUser: true });
    const activeOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
    if (activeOrder) {
      await this._sendExistingPublicOrder(chatId, activeOrder, { prefix: 'Возвращаю текущий заказ.' });
      return;
    }

    const profile = await this._latestRenewableProfileForUser(user, chatId);
    if (!profile) {
      await this._renderOrEdit(
        chatId,
        'Я не нашёл живую подписку, которую можно продлить в этом чате.\n\n' +
          'Если профиль уже был удалён, нужно оформить новый доступ. Если подписка есть, но бот её не видит, напишите в поддержку.',
        {
          replyMarkup: kb([
            [['Вставить другую ссылку', 'public:renew_other', 'primary']],
            [['Купить доступ', 'public:access', 'success']],
            [['Поддержка', 'public:support', 'primary']],
            [['Назад в меню', 'public:menu']],
          ]),
          messageId,
        }
      );
      return;
    }
    await this._sendRenewalOverview(chatId, profile, { messageId });
  }

  async showPublicRenewDevices(chatId, profilePublicId, { messageId = null } = {}) {
    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const currentLimit = Number(target.device_limit);
    const rows = [3, 6, 9].map((limit) => {
      const suffix = limit === currentLimit ? ' · текущий' : '';
      return [
        [
          `${ShopBot._devicePlanTitle(limit)} · до ${limit} устройств${suffix}`,
          `public:renew_duration:${target.profile.public_id}:${limit}`,
        ],
      ];
    });
    rows.push([['Назад', 'public:renew']]);
    await this._renderOrEdit(chatId, 'Выберите лимит устройств для следующего оплаченного периода.', {
      replyMarkup: kb(rows),
      messageId,
    });
  }

  async showPublicRenewDuration(chatId, profilePublicId, deviceLimit, { messageId = null } = {}) {
    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const transport = String(target.transport);
    const context = ShopBot._contextFromSession(await this.store.getSession(chatId));
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const discount = discountPromo ? Number(discountPromo.discount_percent) : 0;

    const rows = [30, 90, 180, 360].map((days) => {
      const price = this.basePriceForDuration(transport, days, { deviceLimit });
      const finalPrice = Math.max(Math.floor((price * (100 - discount)) / 100), 0);
      return [
        [
          `${ShopBot._durationLabel(days)} · ${finalPrice} RUB`,
          `public:renew_preview:${target.profile.public_id}:${deviceLimit}:${days}`,
        ],
      ];
    });
    rows.push([['Назад', `public:renew_devices:${target.profile.public_id}`]]);
    await this._renderOrEdit(
      chatId,
      `Лимит: ${ShopBot.deviceLimitLabel(deviceLimit)}. Теперь выберите срок продления.`,
      { replyMarkup: kb(rows), messageId }
    );
  }

  async showPublicRenewConfirm(
    chatId,
    profilePublicId,
    { durationDays, deviceLimit, messageId = null }
  ) {
    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const context = ShopBot._contextFromSession(await this.store.getSession(chatId));
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const price = this.basePriceForDuration(String(target.transport), durationDays, { deviceLimit });
    const finalPrice = discountPromo
      ? Math.max(Math.floor((price * (100 - Number(discountPromo.discount_percent))) / 100), 0)
      : price;
    const priceLine = discountPromo ? `${price} -> ${finalPrice} RUB по промокоду` : `${finalPrice} RUB`;

    await this._renderOrEdit(
      chatId,
      [
        'Проверьте продление',
        '',
        `Профиль: ${target.profile.xui_email}`,
        `Режим: ${ShopBot.transportLabel(String(target.transport))}`,
        `Текущий срок до: ${ShopBot.formatTs(target.expires_at)}`,
        `Новый оплаченный период: ${ShopBot._durationLabel(durationDays)}`,
        `Лимит после оплаты: ${ShopBot.deviceLimitLabel(deviceLimit)}`,
        `К оплате: ${priceLine}`,
        '',
        '💡 Комиссия шлюза оплачивается покупателем. Для прямой оплаты без комиссии обратитесь к менеджеру через кнопку «Поддержка».',
      ].join('\n'),
      {
        replyMarkup: kb([
          [
            [
              'Перейти к оплате',
              `public:renew_confirm:${target.profile.public_id}:${durationDays}:${deviceLimit}`,
              'success',
            ],
          ],
          [['Изменить срок', `public:renew_duration:${target.profile.public_id}:${deviceLimit}`]],
          [['💬 Поддержка', this.settings.supportTgUrl || 'https://t.me/SilentConnectHelp']],
          [['Назад', `public:renew_devices:${target.profile.public_id}`]],
        ]),
        messageId,
      }
    );
  }

  static _remainingDaysUntil(expiresAt) {
    const seconds = Number(expiresAt || 0) - nowTs();
    return Math.max(Math.floor((seconds + 86399) / 86400), 0);
  }

  _upgradePrice(transport, remainingDays, currentLimit, targetLimit) {
    const curPrice = this.basePriceForDuration(transport, remainingDays, { deviceLimit: currentLimit });
    const tgtPrice = this.basePriceForDuration(transport, remainingDays, { deviceLimit: targetLimit });
    return Math.max(tgtPrice - curPrice, 0);
  }

  async showPublicUpgradeDevices(chatId, profilePublicId, { messageId = null } = {}) {
    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const currentLimit = Number(target.device_limit);
    const remainingDays = ShopBot._remainingDaysUntil(target.expires_at);
    if (remainingDays <= 0) {
      await this._renderOrEdit(chatId, 'Текущий срок уже закончился. Выберите обычное продление.', {
        messageId,
      });
      await this.showPublicRenewDevices(chatId, String(target.profile.public_id));
      return;
    }
    const rows = [];
    for (const limit of [3, 6, 9]) {
      if (limit <= currentLimit) continue;
      const price = this._upgradePrice(String(target.transport), remainingDays, currentLimit, limit);
      rows.push([
        [
          `До ${limit} устройств · доплата ${price} RUB`,
          `public:upgrade_preview:${target.profile.public_id}:${limit}`,
        ],
      ]);
    }
    if (!rows.length) {
      rows.push([['Продлить на новый срок', `public:renew_devices:${target.profile.public_id}`, 'success']]);
    }
    rows.push([['Назад', 'public:renew']]);
    await this._renderOrEdit(
      chatId,
      `До конца текущего срока осталось примерно ${remainingDays} дн. Выберите новый лимит.`,
      { replyMarkup: kb(rows), messageId }
    );
  }

  async showPublicUpgradeConfirm(chatId, profilePublicId, deviceLimit, { messageId = null } = {}) {
    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId, { messageId });
      return;
    }
    const currentLimit = Number(target.device_limit);
    const remainingDays = ShopBot._remainingDaysUntil(target.expires_at);
    if (remainingDays <= 0 || deviceLimit <= currentLimit) {
      await this.showPublicUpgradeDevices(chatId, String(target.profile.public_id), { messageId });
      return;
    }
    const basePrice = this._upgradePrice(String(target.transport), remainingDays, currentLimit, deviceLimit);
    const context = ShopBot._contextFromSession(await this.store.getSession(chatId));
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const finalPrice = discountPromo
      ? Math.max(Math.floor((basePrice * (100 - Number(discountPromo.discount_percent))) / 100), 0)
      : basePrice;
    const priceLine = discountPromo ? `${basePrice} -> ${finalPrice} RUB по промокоду` : `${finalPrice} RUB`;

    await this._renderOrEdit(
      chatId,
      [
        'Проверьте изменение лимита',
        '',
        `Профиль: ${target.profile.xui_email}`,
        `Текущий лимит: ${ShopBot.deviceLimitLabel(currentLimit)}`,
        `Новый лимит: ${ShopBot.deviceLimitLabel(deviceLimit)}`,
        `Срок не меняется: до ${ShopBot.formatTs(target.expires_at)}`,
        `Доплата за оставшиеся ${remainingDays} дн.: ${priceLine}`,
      ].join('\n'),
      {
        replyMarkup: kb([
          [
            [
              'Перейти к оплате',
              `public:upgrade_confirm:${target.profile.public_id}:${deviceLimit}`,
              'success',
            ],
          ],
          [['Назад', `public:upgrade_devices:${target.profile.public_id}`]],
        ]),
        messageId,
      }
    );
  }

  async promptPublicRenewalLink(chatId, { messageId = null } = {}) {
    const context = ShopBot._contextFromSession(await this.store.getSession(chatId));
    context.promo_return = 'renewal';
    await this.store.setSession(chatId, 'public', 'await_renewal_subscription_url', context);
    await this._renderOrEdit(
      chatId,
      `Отправьте подписочную ссылку одним сообщением. Подойдёт ссылка вида ${this.settings.subscriptionBaseUrl}/...`,
      {
        replyMarkup: kb([[['« Назад', 'public:renew']], [['💬 Поддержка', 'public:support']]]),
        messageId,
      }
    );
  }

  async handleRenewalSubscriptionUrlInput(chatId, text, session, user) {
    const raw = String(text || '').trim();
    const match = raw.match(/https?:\/\/[^\s<>[\]()"']+/);
    const subUrl = match ? match[0] : '';
    if (!subUrl) {
      await this.sendMessage(chatId, 'Не увидел ссылку. Отправьте именно URL подписки или страницы подключения.');
      return;
    }
    const subId = ShopBot._subscriptionIdFromUrl(subUrl).split('~')[0].trim();
    if (!subId) {
      await this.sendMessage(chatId, 'Не нашёл ID подписки в ссылке.');
      return;
    }
    const found = await this.provisioner.findClientBySubId(subId);
    if (!found) {
      await this.sendMessage(
        chatId,
        'Этой подписки нет на сервере. Проверьте ссылку или напишите в поддержку.',
        {
          replyMarkup: kb([
            [['Попробовать другую ссылку', 'public:renew_other']],
            [['Поддержка', 'public:support', 'primary']],
          ]),
        }
      );
      return;
    }
    const email = String(found.client?.email || '');
    let profile = await this.store.getProfileByXuiEmail(email);
    if (!profile) {
      profile = await this.store.ensureProfileForXuiClient(
        found.inbound_id || 2,
        found.client || {},
        String(found.protocol || 'tcp')
      );
    }
    const notes = String(profile.notes || '').toLowerCase();
    if (
      !notes.includes('admin_personal') &&
      !String(profile.xui_email || '').startsWith('admin-') &&
      ([TEST_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES].includes(profile.notes) ||
        notes.includes('trial') ||
        notes.includes('test') ||
        notes.includes('auto_delete'))
    ) {
      await this.sendMessage(
        chatId,
        'Пробную подписку (7 дней) или тестовый профиль нельзя продлить через обычную оплату.'
      );
      return;
    }
    const order = await this.store.getOrderForProfile(String(profile.public_id));
    await this.store.linkProfileOwner({
      profilePublicId: String(profile.public_id),
      userId: user?.id || chatId,
      chatId,
      sourceOrderPublicId: order ? String(order.public_id) : null,
    });
    const context = ShopBot._contextFromSession(session);
    context.renewal_profile_public_id = String(profile.public_id);
    if (order) context.order_public_id = String(order.public_id);
    await this.store.setSession(chatId, 'public', 'renewal_menu', context);
    await this._sendRenewalOverview(chatId, profile, {
      prefix: 'Ссылка принята и привязана к этому Telegram.',
    });
  }

  // --- Создание и завершение заказов ---
  async createStandardOrder(chatId, offer) {
    const session = (await this.store.getSession(chatId)) || {
      scope: 'public',
      state: 'menu',
      context_json: {},
    };
    const context = ShopBot._contextFromSession(session);
    const discountPromo = await this._activeDiscountPromoFromContext(context);
    if (context.discount_promo_id && !discountPromo) {
      delete context.discount_promo_id;
      delete context.discount_promo;
      await this.store.setSession(chatId, 'public', String(session.state || 'menu'), context);
      await this.sendMessage(
        chatId,
        'Промокод уже недействителен или был использован. Введите другой код или выберите тариф без скидки.'
      );
      await this.showPublicAccessMenu(chatId);
      return;
    }

    let actionKey = `public:buy:${offer.code}`;
    if (discountPromo) actionKey = `${actionKey}:discount:${Number(discountPromo.id)}`;

    const [claimed] = await this._claimAction(chatId, {
      scope: 'public',
      state: String(session.state || 'menu'),
      actionKey,
      context,
    });
    if (!claimed) {
      await this._notifyActionInFlight(chatId);
      return;
    }

    try {
      const activeOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
      if (activeOrder) {
        await this._clearActionIfMatches(chatId, actionKey);
        await this._sendExistingPublicOrder(chatId, activeOrder, { prefix: 'Возвращаю текущий заказ.' });
        return;
      }

      const promoDiscount = discountPromo ? Number(discountPromo.discount_percent) : 0;
      let refDiscount = 0;
      const attr = await this.store.getReferralAttributionForUser(chatId);
      if (attr) {
        const priorPaid = await this.store.countDeliveredPaidOrders({ customerChatId: chatId });
        if (priorPaid === 0) refDiscount = REFERRAL_INVITEE_DISCOUNT_PERCENT;
      }

      const discountPercent = Math.max(promoDiscount, refDiscount);
      const finalPrice = Math.max(Math.floor((offer.priceRub * (100 - discountPercent)) / 100), 0);
      const meta = { source: offer.code, device_limit: offer.deviceLimit };
      if (discountPromo) meta.promo_type = 'discount';
      if (attr && refDiscount > 0) {
        meta.referrer_id = attr.referrer_id;
        meta.referral_discount = refDiscount;
      }

      const order = await this.store.createOrder({
        kind: 'purchase',
        status: finalPrice > 0 ? 'waiting_payment' : 'auto_provision',
        transport: offer.transport,
        durationDays: offer.durationDays,
        profileMode: offer.profileMode,
        familyLabel: null,
        basePriceRub: offer.priceRub,
        finalPriceRub: finalPrice,
        promoId: discountPromo ? Number(discountPromo.id) : null,
        inviteId: context.invite_id || null,
        customerChatId: chatId,
        privacyAck: true,
        lossPolicyAck: true,
        termsVersion: this.settings.termsVersion,
        meta,
      });

      if (context.invite_id) {
        const consumed = await this.store.consumeInvite(context.invite_id);
        if (!consumed && this.settings.inviteRequired) {
          await this.sendMessage(chatId, 'Приглашение уже использовано или недействительно.');
          await this.showPublicMenu(chatId);
          return;
        }
      }

      delete context.discount_promo;
      delete context.discount_promo_id;
      context.order_public_id = order.public_id;

      if (finalPrice === 0) {
        await this.completeOrder(order, 'system-auto-discount-promo', {
          deliveryPrefix: 'Промокод применён. Ваша ссылка:',
        });
        return;
      }

      await this._completeAction(chatId, {
        scope: 'public',
        state: 'waiting_payment',
        context,
        actionKey,
        resultKind: 'order',
        order_public_id: order.public_id,
      });
      const msg = await this._waitingPaymentMessage(order);
      const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
      await this.sendMessage(chatId, msg, { replyMarkup: markup });
      await this.notifyAdminsAboutOrder(order);
    } catch (err) {
      await this._clearActionIfMatches(chatId, actionKey);
      throw err;
    }
  }

  async createRenewalOrder(
    chatId,
    user,
    profilePublicId,
    durationDays = 30,
    { deviceLimit = null, upgradeOnly = false } = {}
  ) {
    const session = (await this.store.getSession(chatId)) || {
      scope: 'public',
      state: 'menu',
      context_json: {},
    };
    const context = ShopBot._contextFromSession(session);
    const userId = String(user?.id || chatId);
    const owner = await this.store.getProfileOwner(profilePublicId);
    if (!owner || String(owner.user_id) !== userId) {
      await this.sendMessage(
        chatId,
        'Эта подписка не привязана к вашему Telegram-аккаунту. Можно оформить новый доступ или написать в поддержку.',
        {
          replyMarkup: kb([
            [['Купить доступ', 'public:access', 'success']],
            [['Поддержка', 'public:support', 'primary']],
          ]),
        }
      );
      return;
    }

    const target = await this._renewalTarget(profilePublicId);
    if (!target) {
      await this._sendRenewalTargetMissing(chatId);
      return;
    }
    const profile = target.profile;
    const renewalTransport = String(target.transport);
    const currentDeviceLimit = Number(target.device_limit);
    const targetDeviceLimit = Number(deviceLimit != null ? deviceLimit : currentDeviceLimit);
    const orderDurationDays = upgradeOnly ? 0 : Number(durationDays);
    const remainingDays = ShopBot._remainingDaysUntil(target.expires_at);

    const price = upgradeOnly
      ? this._upgradePrice(renewalTransport, remainingDays, currentDeviceLimit, targetDeviceLimit)
      : this.basePriceForDuration(renewalTransport, orderDurationDays, {
          deviceLimit: targetDeviceLimit,
        });

    const discountPromo = await this._activeDiscountPromoFromContext(context);
    const discountPercent = discountPromo ? Number(discountPromo.discount_percent) : 0;
    const finalPrice = Math.max(Math.floor((price * (100 - discountPercent)) / 100), 0);

    const meta = {
      source: upgradeOnly ? 'upgrade' : 'renewal',
      renewal_profile_public_id: String(target.renewal_profile_public_id),
      device_limit: targetDeviceLimit,
      previous_device_limit: currentDeviceLimit,
    };
    if (upgradeOnly) {
      meta.upgrade_only = true;
      meta.remaining_days_at_order = remainingDays;
    }
    if (renewalTransport === 'hybrid') {
      Object.assign(meta, {
        hybrid: true,
        hybrid_renewal: true,
        tcp_profile_public_id: String(target.renewal_profile_public_id),
        xhttp_profile_public_id: String(target.renewal_xhttp_profile_public_id || ''),
        renewal_xhttp_profile_public_id: String(target.renewal_xhttp_profile_public_id || ''),
      });
    }
    if (discountPromo) meta.promo_type = 'discount';

    const order = await this.store.createOrder({
      kind: 'renewal',
      status: finalPrice > 0 ? 'waiting_payment' : 'auto_provision',
      transport: renewalTransport,
      durationDays: orderDurationDays,
      profileMode: String(profile.profile_mode),
      familyLabel: profile.family_label,
      basePriceRub: price,
      finalPriceRub: finalPrice,
      promoId: discountPromo ? Number(discountPromo.id) : null,
      inviteId: null,
      customerChatId: chatId,
      privacyAck: true,
      lossPolicyAck: true,
      termsVersion: this.settings.termsVersion,
      meta,
    });

    delete context.discount_promo;
    delete context.discount_promo_id;
    delete context.promo_return;
    context.order_public_id = order.public_id;

    if (finalPrice === 0) {
      await this.completeOrder(order, 'system-auto-discount-promo', {
        deliveryPrefix: upgradeOnly
          ? 'Промокод применён. Лимит подписки обновлён, ссылка прежняя:'
          : 'Промокод применён. Подписка продлена, ссылка прежняя:',
      });
      return;
    }

    await this.store.setSession(chatId, 'public', 'waiting_payment', context);
    const msg = await this._waitingPaymentMessage(order);
    const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
    await this.sendMessage(chatId, msg, { replyMarkup: markup });
    await this.notifyAdminsAboutOrder(order);
  }

  async completeOrder(
    order,
    actor,
    { deliveryPrefix = 'Оплата подтверждена. Ваша ссылка:' } = {}
  ) {
    let result;
    let completedNow = false;

    if (order.status === 'delivered' && order.provisioned_profile_id) {
      result = await this._recoverSubscriptionForOrder(order);
    } else {
      order = await this.store.transitionOrder(order.public_id, 'provisioning', {
        expectedFrom: ['waiting_payment', 'auto_provision', 'failed'],
        actor,
        reason: 'complete_order_start',
      });

      const promoId = order.promo_id;
      if (promoId) {
        const consumed = await this.store.consumePromoCode(Number(promoId));
        if (!consumed) {
          await this.store.transitionOrder(order.public_id, 'failed', {
            expectedFrom: ['provisioning'],
            actor,
            reason: 'promo_exhausted',
          });
          throw new Error(`Promo code for order ${order.public_id} is exhausted`);
        }
      }

      try {
        if (order.kind === 'renewal') {
          const meta = order.meta_json || {};
          const profilePublicId = String(meta.renewal_profile_public_id || '');
          const deviceLimit = Number(meta.device_limit ?? this.settings.defaultDeviceLimit);

          if (order.transport === 'hybrid' || meta.hybrid) {
            const xhttpId = String(
              meta.renewal_xhttp_profile_public_id || meta.xhttp_profile_public_id || ''
            );
            const tcpRes = await this.provisioner.renewProfile(
              profilePublicId,
              Number(order.duration_days),
              { deviceLimit }
            );
            const xhttpRes = await this.provisioner.renewProfile(
              xhttpId,
              Number(order.duration_days),
              { deviceLimit }
            );
            result = {
              profile: tcpRes.profile,
              xhttp_profile: xhttpRes.profile,
              subscription_url: this._hybridSubscriptionUrl(String(tcpRes.sub_id), String(xhttpRes.sub_id)),
              sub_id: `${tcpRes.sub_id}~${xhttpRes.sub_id}`,
              expires_at: Math.min(Number(tcpRes.expires_at), Number(xhttpRes.expires_at)),
            };
          } else {
            result = await this.provisioner.renewProfile(
              profilePublicId,
              Number(order.duration_days),
              { deviceLimit }
            );
          }
          await this.store.linkOrderProfile(order.public_id, result.profile.public_id);
          await this.store.updateOrderStatus(order.public_id, 'delivered', { actor });
          completedNow = true;
          if (deliveryPrefix === 'Оплата подтверждена. Ваша ссылка:') {
            deliveryPrefix = meta.upgrade_only
              ? 'Оплата подтверждена. Лимит подписки обновлён, ссылка прежняя:'
              : 'Оплата подтверждена. Подписка продлена, ссылка прежняя:';
          }
        } else {
          result = await this.provisioner.createProfileForOrder(order);
          if (result?.status === 'pending_provision') {
            if (order.customer_chat_id) {
              const queueMsg =
                result.userMessage ||
                '⏳ Оплата получена! Активация подписки поставлена в очередь и придёт автоматически в течение пары минут.';
              await this.sendMessage(order.customer_chat_id, queueMsg);
            }
            await this.notifyAdminsAboutOrder(
              order,
              '⚠️ Заказ ожидает активации (ноды временно недоступны)'
            );
            return result;
          }
          await this.store.updateOrderStatus(order.public_id, 'delivered', { actor });
          completedNow = true;
          if (!result.subscription_url) {
            const refreshed = await this.store.getOrder(order.public_id);
            result = await this._recoverSubscriptionForOrder(refreshed || order);
          }
        }
      } catch (err) {
        if (promoId) await this.store.restorePromoCode(Number(promoId));
        await this.store.transitionOrder(order.public_id, 'failed', {
          expectedFrom: ['provisioning'],
          actor,
          reason: 'provisioning_failed',
        });
        throw err;
      }
    }

    if (completedNow) {
      try {
        const [ledger, oldBalance, newBalance] = await this.store.createReferralLedgerForOrder(order);
        if (ledger) {
          const refInfo = await this.store.getReferralBalance(Number(ledger.referrer_id));
          if (refInfo?.chat_id) {
            await this.sendMessage(
              refInfo.chat_id,
              `💰 Реферальное начисление! Заказ #${order.public_id}. ` +
                `Сумма покупки: ${ledger.base_amount_rub} RUB. Вам начислено: +${ledger.amount_rub} RUB (${ledger.commission_percent}%). ` +
                `Баланс: ${newBalance} RUB.`
            );
          }
          if (oldBalance < REFERRAL_PAYOUT_MIN_RUB && newBalance >= REFERRAL_PAYOUT_MIN_RUB) {
            await this.notifyAdminsReferralThreshold(Number(ledger.referrer_id), newBalance);
          }
        }
      } catch (err) {
        console.error(`Failed referral accrual for ${order.public_id}:`, err);
      }

      const customerEmail = String(
        order.customer_email || order.meta_json?.customer_email || ''
      ).trim();
      if (customerEmail && result?.subscription_url) {
        try {
          const webToken = String(order.meta_json?.web_token || '');
          const cabinetUrl = webToken
            ? `${this.settings.webPublicBaseUrl}/order/${encodeURIComponent(order.public_id)}/${encodeURIComponent(webToken)}`
            : this.settings.webPublicBaseUrl;
          await this.provisioner.sendSubscriptionEmail({
            customer_email: customerEmail,
            order_public_id: String(order.public_id),
            plan_name: `SilentConnect (${order.duration_days || 30} дн.)`,
            duration_days: Number(order.duration_days || 30),
            setup_url: ShopBot._subscriptionSetupUrl(result.subscription_url),
            json_url: result.subscription_url,
            cabinet_url: cabinetUrl,
            expires_ts: result.profile?.expires_at,
          });
        } catch (e) {
          console.error(`Failed to send subscription email for ${order.public_id}:`, e);
        }
      }
    }

    const customerChatId = order.customer_chat_id;
    if (customerChatId != null) {
      await this.store.linkProfileOwner({
        profilePublicId: result.profile.public_id,
        userId: customerChatId,
        chatId: customerChatId,
        sourceOrderPublicId: order.public_id,
      });
      await this._mergeSessionState(customerChatId, 'public', 'menu', {
        order_public_id: order.public_id,
      });
      await this._sendPublicSubscription(customerChatId, result.subscription_url, {
        prefix: deliveryPrefix,
      });
      if (order.profile_mode === 'anonymous') {
        await this.store.clearOrderCustomerContact(order.public_id);
      }
    }
    return result;
  }

  // --- Пробный период, Рефералы, Промокоды ---
  async createPublicTrial(chatId, user, { messageId = null } = {}) {
    const userId = String(user?.id || chatId);
    const redemption = await this.store.getTrialRedemption(userId);
    if (redemption && redemption.status === 'delivered') {
      await this._renderOrEdit(
        chatId,
        'Бесплатная неделя уже была использована на этом Telegram-аккаунте.',
        {
          replyMarkup: kb([
            [['Купить доступ', 'public:access', 'success']],
            [['Назад в меню', 'public:menu']],
          ]),
          messageId,
        }
      );
      return;
    }

    const [claimed] = await this.store.claimTrialRedemption({
      userId,
      chatId,
      transport: TRIAL_TRANSPORT,
    });
    if (!claimed) {
      await this.sendMessage(chatId, 'Бесплатная неделя уже создаётся. Дождитесь сообщения со ссылкой.');
      return;
    }

    try {
      const result = await this.provisioner.createPublicTrialProfile(user, TRIAL_TRANSPORT);
      await this.store.markTrialDelivered({
        userId,
        profilePublicId: result.profile.public_id,
      });
      await this.store.recordAdminAction({
        actionType: 'create_public_trial',
        targetType: 'profile',
        targetPublicId: result.profile.public_id,
        actor: `tg:${userId}`,
        meta: { transport: TRIAL_TRANSPORT, xui_email: result.xui_email },
      });
      await this._sendPublicSubscription(chatId, result.subscription_url, {
        prefix: 'Бесплатная неделя активирована. Ваша ссылка:',
      });
    } catch (err) {
      console.error(`Failed public trial for ${userId}:`, err);
      await this.store.markTrialFailed({ userId, error: String(err) });
      await this.sendMessage(
        chatId,
        'Не получилось создать пробный доступ. Попробуйте ещё раз через пару минут или напишите в поддержку.',
        {
          replyMarkup: kb([
            [['Поддержка', 'public:support', 'primary']],
            [['Назад в меню', 'public:menu']],
          ]),
        }
      );
    }
  }

  async showPublicReferral(chatId, user, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    const userId = String(user?.id || chatId);
    const referrer = await this.store.getReferrerByUser(userId);
    if (referrer) {
      const balance = (await this.store.getReferralBalance(Number(referrer.id))) || {};
      const refCode = String(referrer.code);
      const botLink = this.referralLink(refCode);
      const webLink = this.webReferralLink(refCode);
      const balanceRub = Number(balance.balance_rub || 0);
      const referredCount = Number(balance.referred_count || 0);
      await this._renderOrEdit(
        chatId,
        [
          '🤝 Реферальная программа',
          '',
          'Ваши персональные ссылки для приглашения:',
          '',
          `🌐 Для покупок на сайте:\n${webLink}`,
          '',
          `📱 Для покупок в Telegram-боте:\n${botLink}`,
          '',
          `• Ваша комиссия: ${Number(referrer.commission_percent)}% с каждой оплаты`,
          '• Скидка другу: 10% на первую подписку (и на сайте, и в боте)',
          `• Баланс к выплате: ${balanceRub} RUB`,
          `• Приглашено друзей: ${referredCount}`,
          `• Минимальная выплата: ${REFERRAL_PAYOUT_MIN_RUB} RUB`,
          '',
          'Начисления поступают автоматически после подтверждения оплаты заказа приглашённым другом.',
        ].join('\n'),
        {
          replyMarkup: kb([
            [{ text: '🌐 Скопировать ссылку на сайт', copy_text: webLink, style: 'primary' }],
            [{ text: '📱 Скопировать ссылку в бота', copy_text: botLink, style: 'primary' }],
            [['Назад в меню', 'public:menu']],
          ]),
          messageId,
        }
      );
      return;
    }

    await this._renderOrEdit(
      chatId,
      [
        '🤝 Реферальная программа',
        '',
        `Вы получаете ${REFERRAL_COMMISSION_PERCENT}% с каждой подтверждённой покупки приглашённого пользователя, а ваш друг получает скидку 10% на первую подписку.`,
        '',
        'Программа действует как для покупок на сайте, так и в Telegram-боте.',
        `Выплаты осуществляются вручную от ${REFERRAL_PAYOUT_MIN_RUB} RUB, остаток переносится дальше.`,
        '',
        'После подключения бот сразу выдаст ваши персональные ссылки (на сайт и в бота).',
      ].join('\n'),
      {
        replyMarkup: kb([
          [['Хочу участвовать', 'public:referral_join', 'success']],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async joinPublicReferral(chatId, user, { messageId = null } = {}) {
    const userId = String(user?.id || chatId);
    const referrer = await this.store.ensureReferrer({
      userId,
      chatId,
      commissionPercent: REFERRAL_COMMISSION_PERCENT,
    });
    const refCode = String(referrer.code);
    const botLink = this.referralLink(refCode);
    const webLink = this.webReferralLink(refCode);
    await this._renderOrEdit(
      chatId,
      [
        '🤝 Вы успешно подключились к реферальной программе!',
        '',
        'Ваши персональные ссылки для приглашения:',
        '',
        `🌐 Для покупок на сайте:\n${webLink}`,
        '',
        `📱 Для покупок в Telegram-боте:\n${botLink}`,
        '',
        `• Ваша комиссия: ${Number(referrer.commission_percent)}% с каждой оплаты`,
        '• Скидка другу: 10% на первую покупку (и на сайте, и в боте)',
        `• Выплата: от ${REFERRAL_PAYOUT_MIN_RUB} RUB вручную.`,
        '',
        'Отправляйте друзьям любую удобную ссылку — обе привязаны к вашему профилю!',
      ].join('\n'),
      {
        replyMarkup: kb([
          [{ text: '🌐 Скопировать ссылку на сайт', copy_text: webLink, style: 'primary' }],
          [{ text: '📱 Скопировать ссылку в бота', copy_text: botLink, style: 'primary' }],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async _sendPublicPromoPrompt(
    chatId,
    { prefix = null, messageId = null, promoReturn = null } = {}
  ) {
    const session = await this.store.getSession(chatId);
    const context = ShopBot._contextFromSession(session);
    delete context.pending_promo;
    delete context.pending_promo_id;
    if (promoReturn) {
      context.promo_return = promoReturn;
    } else {
      delete context.promo_return;
      delete context.renewal_profile_public_id;
    }
    await this.store.setSession(chatId, 'public', 'await_promo_code', context);
    let message = 'Отправьте промокод одним сообщением без лишних символов.';
    if (prefix) message = `${prefix}\n\n${message}`;
    await this._renderOrEdit(chatId, message, {
      replyMarkup: kb([[['« Назад в меню', 'public:menu']]]),
      messageId,
    });
  }

  async handlePromoInput(chatId, text, session) {
    const promo = await this.store.findValidPromo(text);
    if (!promo) {
      await this.sendMessage(chatId, 'Промокод не найден или уже недействителен.');
      await this.showPublicMenu(chatId, 'Попробуйте другой код или вернитесь в витрину.');
      return;
    }

    const context = ShopBot._contextFromSession(session);
    context.pending_promo_id = promo.id;
    context.pending_promo = promo;

    if (ShopBot.promoType(promo) === 'discount') {
      const promoReturn = String(context.promo_return || '');
      delete context.pending_promo_id;
      delete context.pending_promo;
      context.discount_promo_id = promo.id;
      context.discount_promo = promo;
      await this.store.setSession(chatId, 'public', 'menu', context);
      await this.sendMessage(
        chatId,
        `Промокод принят. Скидка ${Number(promo.discount_percent)}% применится к тарифу, который вы выберете.`
      );
      if (promoReturn === 'renewal') {
        const profileId = String(context.renewal_profile_public_id || '');
        const profile = profileId ? await this.store.getProfile(profileId) : null;
        if (profile) {
          await this._sendRenewalOverview(chatId, profile);
          return;
        }
        await this.showPublicRenewal(chatId, { id: chatId });
        return;
      }
      await this.showPublicAccessMenu(chatId);
      return;
    }

    if (promo.profile_mode === 'family') {
      await this.store.setSession(chatId, 'public', 'await_family_privacy_ack', context);
      await this.sendMessage(
        chatId,
        `Промокод привязан к профилю \`${promo.family_label}\`.\nТакой профиль не полностью анонимен. Согласны продолжить?`,
        {
          replyMarkup: kb([
            [['Согласен', 'public:family_accept']],
            [['Хочу остаться анонимным', 'public:family_decline']],
          ]),
        }
      );
      return;
    }

    await this.createPromoOrder(chatId, promo, context);
  }

  async createPromoOrder(chatId, promo, context) {
    const durationDays = Number(promo.duration_days);
    const deviceLimit = this.promoDeviceLimit(promo);
    const basePrice = this.basePriceForDuration(promo.transport, durationDays, { deviceLimit });
    const finalPrice = ShopBot.fixedPromoFinalPrice(promo, basePrice);

    const reserved = await this.store.getOpenOrderForPromo(Number(promo.id));
    if (reserved) {
      await this.sendMessage(
        chatId,
        'Этот промокод уже применён в другом открытом заказе. Если это ошибка, напишите в поддержку.',
        {
          replyMarkup: kb([
            [['Поддержка', 'public:support', 'primary']],
            [['Назад в меню', 'public:menu']],
          ]),
        }
      );
      return;
    }

    const order = await this.store.createOrder({
      kind: 'purchase',
      status: finalPrice > 0 ? 'waiting_payment' : 'auto_provision',
      transport: promo.transport,
      durationDays,
      profileMode: promo.profile_mode,
      familyLabel: promo.family_label,
      basePriceRub: basePrice,
      finalPriceRub: finalPrice,
      promoId: promo.id,
      inviteId: context.invite_id || null,
      customerChatId: chatId,
      privacyAck: true,
      lossPolicyAck: true,
      termsVersion: this.settings.termsVersion,
      meta: { source: 'promo', device_limit: deviceLimit },
    });

    if (context.invite_id) {
      const consumed = await this.store.consumeInvite(context.invite_id);
      if (!consumed && this.settings.inviteRequired) {
        await this.sendMessage(chatId, 'Приглашение уже использовано или недействительно.');
        await this.showPublicMenu(chatId);
        return;
      }
    }

    delete context.pending_promo;
    delete context.pending_promo_id;
    context.order_public_id = order.public_id;

    if (finalPrice === 0) {
      await this.completeOrder(order, 'system-auto-promo', {
        deliveryPrefix: 'Промокод применён. Ваша ссылка:',
      });
      return;
    }

    await this.store.setSession(chatId, 'public', 'waiting_payment', context);
    const msg = await this._waitingPaymentMessage(order);
    const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
    await this.sendMessage(chatId, msg, { replyMarkup: markup });
    await this.notifyAdminsAboutOrder(order);
  }

  // --- Инфо-разделы (Help, FAQ, Rules, Support) ---
  async showPublicHelp(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    const text = [
      '📖 Как настроить подключение',
      '',
      '1. Выберите подходящий тариф или введите промокод.',
      '2. Получите персональную ссылку в этом чате.',
      '3. Нажмите «Подключить».',
      '4. На странице выберите устройство и приложение.',
      '5. Добавьте подписку и включите защищенное соединение.',
      '6. Если не получилось, откройте FAQ или поддержку.',
      '',
      `📄 Пользовательское соглашение: ${this.legalTermsUrl()}`,
      `🔒 Политика конфиденциальности: ${this.legalPrivacyUrl()}`,
      `↩️ Политика возвратов: ${this.legalRefundUrl()}`,
      '',
      '[code: mekbuda]',
    ].join('\n');

    await this._renderOrEdit(chatId, text, {
      replyMarkup: kb([
        [['🚀 Выбрать тариф', 'public:access', 'success']],
        [
          ['❓ FAQ', 'public:faq', 'primary'],
          ['💬 Поддержка', 'public:support', 'primary'],
        ],
        [
          ['📄 Соглашение', this.legalTermsUrl()],
          ['🔒 Приватность', this.legalPrivacyUrl()],
        ],
        [
          ['↩️ Возвраты', this.legalRefundUrl()],
          ['📜 Все правила', 'public:rules'],
        ],
        [['« Назад в меню', 'public:menu']],
      ]),
      messageId,
    });
  }

  async showPublicFaq(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    const text = [
      '❓ Часто задаваемые вопросы (FAQ)',
      '',
      '• Сохраняется ли история посещений (логи)?',
      'Нет. На серверах отключена запись истории посещений (access-логи), DNS-запросов и сетевых маршрутов. Временные технические журналы серверов автоматически удаляются каждые 48 часов.',
      '',
      '• Действительно ли трафик безлимитный?',
      'Да, мы не ограничиваем гигабайты и скорость при использовании сервиса. Действует стандартная политика добросовестного использования (Fair Use Policy).',
      '',
      '• На каких устройствах работает подключение?',
      'На любых устройствах: iPhone, iPad, Android, компьютерах Windows, macOS и Linux.',
      '',
      '• Как продлить доступ?',
      'Продление происходит по вашей постоянной ссылке в один клик без необходимости перенастройки устройств.',
      '',
      `📄 Пользовательское соглашение: ${this.legalTermsUrl()}`,
      `🔒 Политика конфиденциальности: ${this.legalPrivacyUrl()}`,
      `↩️ Политика возвратов: ${this.legalRefundUrl()}`,
      '',
      '[code: mekbuda]',
    ].join('\n');

    await this._renderOrEdit(chatId, text, {
      replyMarkup: kb([
        [
          ['📄 Соглашение', this.legalTermsUrl()],
          ['🔒 Приватность', this.legalPrivacyUrl()],
        ],
        [
          ['↩️ Возвраты', this.legalRefundUrl()],
          ['💬 Поддержка', 'public:support', 'primary'],
        ],
        [
          ['📖 Как подключить', 'public:help'],
          ['📜 Все правила', 'public:rules'],
        ],
        [['« Назад в меню', 'public:menu']],
      ]),
      messageId,
    });
  }

  async showPublicRulesMenu(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    await this._renderOrEdit(
      chatId,
      'Правила, приватность и помощь с выдачей ссылки вынесены в отдельные разделы. Выберите нужный пункт:',
      {
        replyMarkup: kb([
          [['📄 Пользовательское соглашение', this.legalTermsUrl()]],
          [['🔒 Политика конфиденциальности', this.legalPrivacyUrl()]],
          [['↩️ Политика возвратов', this.legalRefundUrl()]],
          [
            ['Правила', 'public:rules:general'],
            ['Приватность', 'public:rules:privacy'],
          ],
          [['Как работает выдача ссылки', 'public:rules:delivery']],
          [['Если не получается импорт', 'public:rules:import']],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async showPublicRulesSection(chatId, section, { messageId = null } = {}) {
    const texts = {
      general:
        'Правила\n\n• Ссылку важно хранить аккуратно.\n• Продление возможно по уже выданной ссылке, пока профиль активен.\n• Неоплаченные заказы автоматически закрываются со временем.',
      privacy:
        'Приватность\n\n• Обычные профили оформляются как анонимные.\n• Семейные промокоды могут быть частично подписаны, и это показывается до подтверждения.',
      delivery:
        'Как работает выдача ссылки\n\n1. Пользователь выбирает доступ или вводит промокод.\n2. После подтверждения оплаты бот выдаёт персональную ссылку.\n3. Эта ссылка используется для импорта и продления.',
      import:
        'Если не получается импорт\n\n1. Убедитесь, что открываете именно ту ссылку, которую прислал бот.\n2. Попробуйте импорт из URL или из буфера обмена.\n3. При трудностях напишите в поддержку.',
    };
    await this._renderOrEdit(chatId, texts[section] || texts.general, {
      replyMarkup: kb([
        [['К разделам', 'public:rules']],
        [
          ['Поддержка', 'public:support'],
          ['Назад в меню', 'public:menu'],
        ],
      ]),
      messageId,
    });
  }

  async showPublicSupport(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    const rows = [];
    if (this.settings.supportTgUrl) {
      rows.push([['Написать в поддержку', this.settings.supportTgUrl]]);
    }
    rows.push([['Назад в меню', 'public:menu']]);
    await this._renderOrEdit(
      chatId,
      [
        'Поддержка',
        '',
        'Если нужен доступ, помощь с импортом или повторная проверка текущего заказа, напишите в поддержку.',
        `Контакт: ${this._supportContact()}`,
        '',
        'Если вопрос связан с уже созданным заказом, приложите номер заказа или скриншот экрана.',
      ].join('\n'),
      { replyMarkup: kb(rows), messageId }
    );
  }

  async _sendAccessLocked(chatId, { prefix = null } = {}) {
    const lines = [];
    if (prefix) lines.push(prefix, '');
    lines.push(
      'Оформление доступа в этом чате пока не открыто.',
      '',
      'Покупка включается по персональной ссылке-приглашению.',
      'Промокод можно ввести и без приглашения.',
      '',
      `Поддержка: ${this._supportContact()}`
    );
    await this.sendMessage(chatId, lines.join('\n'), {
      replyMarkup: kb([
        [['У меня есть промокод', 'public:promo']],
        [['Написать в поддержку', this.settings.supportTgUrl || 'https://t.me/SilentConnectHelp']],
        [['Назад в меню', 'public:menu']],
      ]),
    });
  }

  // --- Админка и уведомления ---
  static _adminOrderMarkup(orderPublicId) {
    return kb([
      [['Подтвердить оплату', `admin:confirm:${orderPublicId}`, 'success']],
      [['Отменить заказ', `admin:cancel:${orderPublicId}`, 'danger']],
    ]);
  }

  async notifyAdminsAboutOrder(order, opts = {}) {
    const options = typeof opts === 'string' ? { title: opts } : opts;
    const { bump = false, title = null } = options;
    const adminChats = await this.store.listChatIdsByScope('admin');
    if (!adminChats.length) return;

    const meta = order.meta_json || {};
    const orderType =
      order.kind === 'renewal' && meta.upgrade_only
        ? 'увеличение лимита'
        : order.kind === 'renewal'
          ? 'продление'
          : 'покупка';
    const durationText = meta.upgrade_only ? 'без продления' : `${order.duration_days} дн.`;

    if (bump) {
      const lastBump = await this.store.getLastAdminAction({
        actionType: 'order_notification_bump',
        targetType: 'order',
        targetPublicId: String(order.public_id),
      });
      if (lastBump && nowTs() - Number(lastBump.created_at || 0) < ORDER_NOTIFICATION_BUMP_SECONDS) {
        return;
      }
    }

    const header = title || (bump
      ? `Пользователь снова вернулся к неоплаченному заказу \`${order.public_id}\``
      : `Новый заказ \`${order.public_id}\``);

    const text = [
      header,
      `Тип: ${orderType}`,
      `Транспорт: ${ShopBot.transportLabel(String(order.transport))}`,
      `Режим: ${order.profile_mode}`,
      `Срок: ${durationText}`,
      `Лимит: ${ShopBot.deviceLimitLabel(this.orderDeviceLimit(order))}`,
      `К оплате: ${order.final_price_rub} RUB`,
    ].join('\n');

    const markup = ShopBot._adminOrderMarkup(String(order.public_id));
    for (const adminChat of adminChats) {
      try {
        const sent = await this.sendMessage(adminChat, text, { replyMarkup: markup });
        await this.store.attachManagerMessage(order.public_id, adminChat, sent.message_id);
      } catch (err) {
        console.error(`Failed to notify admin ${adminChat}:`, err);
      }
    }
    if (bump) {
      await this.store.recordAdminAction({
        actionType: 'order_notification_bump',
        targetType: 'order',
        targetPublicId: String(order.public_id),
        actor: 'system-public-resume',
      });
    }
  }

  async notifyAdminsPaymentReported(order, user) {
    const lastReport = await this.store.getLastAdminAction({
      actionType: 'payment_reported_by_customer',
      targetType: 'order',
      targetPublicId: String(order.public_id),
    });
    if (lastReport && nowTs() - Number(lastReport.created_at || 0) < PAYMENT_REPORT_REPEAT_SECONDS) {
      return false;
    }
    const adminChats = await this.store.listChatIdsByScope('admin');
    if (!adminChats.length) return false;

    const uname = normalizeUsername(user?.username);
    const buyer = uname ? `@${uname}` : `tg:${user?.id || order.customer_chat_id}`;
    const text = [
      `Покупатель сообщил об оплате заказа \`${order.public_id}\``,
      `Покупатель: ${buyer}`,
      `Сумма: ${order.final_price_rub} RUB`,
      '',
      'Проверь поступление на счёте и нажми «Подтвердить оплату».',
    ].join('\n');

    const markup = ShopBot._adminOrderMarkup(String(order.public_id));
    for (const adminChat of adminChats) {
      const sent = await this.sendMessage(adminChat, text, { replyMarkup: markup });
      await this.store.attachManagerMessage(order.public_id, adminChat, sent.message_id);
    }
    await this.store.recordAdminAction({
      actionType: 'payment_reported_by_customer',
      targetType: 'order',
      targetPublicId: String(order.public_id),
      actor: `tg:${user?.id || order.customer_chat_id}`,
    });
    return true;
  }

  async sendAdminMenu(chatId, { clearActionGuard = true, messageId = null } = {}) {
    const dropKeys = clearActionGuard ? [ACTION_GUARD_KEY] : [];
    await this._mergeSessionState(chatId, 'admin', 'menu', { admin: true }, { dropKeys });
    const text = '⚙️ Админ-меню SilentConnect\n\nВыберите раздел для управления:';
    await this._renderOrEdit(chatId, text, {
      replyMarkup: kb([
        [
          ['🎫 Создать инвайт', 'admin:create_invite'],
          ['🎟 Создать промокод', 'admin:create_promo'],
        ],
        [
          ['🤝 Рефералы', 'admin:referrals', 'primary'],
          ['📊 Сервер и статус', 'admin:server', 'primary'],
        ],
        [
          ['🔗 Публичная ссылка', 'admin:public_link'],
          ['🚀 Поделиться WARP', 'admin:share_warp', 'primary'],
        ],
        [
          ['👤 Админ-конфиг', 'admin:create_personal_config'],
          ['⏱ Тест 24ч', 'admin:create_test_config'],
        ],
        [['⚡ Универсальный тест', 'admin:create_hybrid_test_config', 'primary']],
        [['🚨 Аварийный переезд', 'admin:failover', 'danger']],
      ]),
      messageId,
    });
  }

  static _displayUser(row) {
    const uname = String(row?.username || '').trim();
    if (uname) return `@${uname}`;
    const name = [row?.first_name, row?.last_name].filter(Boolean).join(' ').trim();
    return name || `id ${row?.user_id || row?.chat_id}`;
  }


  async showAdminFailover(chatId, { messageId = null } = {}) {
    const baseDomain = process.env.BASE_DOMAIN || process.env.DOMAIN_MAIN || 'example.com';
    const text = [
      '🚨 *Аварийный переезд кластера (Disaster Recovery)*\n',
      'Выберите целевой узел для переключения основных доменов:',
      '• `${baseDomain}` (Магазин и витрина)',
      '• `sub.${baseDomain}` (Подписки и кабинет)',
      '• `edge.${baseDomain}` (Reality / gRPC / Hysteria)\n',
      '💡 *IP-адрес не захардкожен*: он динамически берётся из системной A-записи выбранной страны.',
    ].join('\n');

    const markup = kb([
      [['🇵🇱 Польша (pl.${baseDomain})', 'admin:failover:confirm:pl']],
      [['🇫🇮 Финляндия (fi.${baseDomain})', 'admin:failover:confirm:fi']],
      [['🇳🇱 Нидерланды (nl.${baseDomain})', 'admin:failover:confirm:nl']],
      [['« Назад в админ-меню', 'admin:menu']],
    ]);
    await this._renderOrEdit(chatId, text, { replyMarkup: markup, messageId });
  }

  async showAdminFailoverConfirm(chatId, countryCode, { messageId = null } = {}) {
    const baseDomain = process.env.BASE_DOMAIN || process.env.DOMAIN_MAIN || 'example.com';
    const countryMap = {
      pl: { name: '🇵🇱 Польша', domain: 'pl.${baseDomain}' },
      fi: { name: '🇫🇮 Финляндия', domain: 'fi.${baseDomain}' },
      nl: { name: '🇳🇱 Нидерланды', domain: 'nl.${baseDomain}' },
    };
    const cinfo = countryMap[String(countryCode || '').toLowerCase()];
    if (!cinfo) {
      return this.sendAdminMenu(chatId, { messageId });
    }

    // Resolve IP dynamically via DNS over HTTPS (Cloudflare 1.1.1.1)
    let resolvedIp = '';
    try {
      const doh = await fetch(`https://cloudflare-dns.com/dns-query?name=${cinfo.domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      });
      const data = await doh.json();
      resolvedIp = (data.Answer && data.Answer[0] && data.Answer[0].data) || '';
    } catch (_) {}

    if (!resolvedIp) {
      // Fallback: system lookup or report
      resolvedIp = cinfo.domain;
    }

    const text = [
      '⚠️ *ПОДТВЕРЖДЕНИЕ АВАРИЙНОГО ПЕРЕЕЗДА*\n',
      `Целевой узел: *${cinfo.name}*`,
      `Системный домен: \`${cinfo.domain}\``,
      `Определённый IP: \`${resolvedIp}\`\n`,
      'Все основные домены будут немедленно переключены в Cloudflare на этот IP со строгим флагом *DNS-Only ⚪* (proxied: false).',
      'Время распространения в глобальном DNS: ~60 секунд.\n',
      'Вы уверены, что хотите выполнить переключение?',
    ].join('\n');

    const markup = kb([
      [[`💥 ДА, ПЕРЕКЛЮЧИТЬ НА ${countryCode.toUpperCase()}`, `admin:failover:apply:${countryCode}`, 'danger']],
      [['❌ Отмена', 'admin:failover']],
    ]);
    await this._renderOrEdit(chatId, text, { replyMarkup: markup, messageId });
  }

  async executeAdminFailover(chatId, countryCode, { messageId = null } = {}) {
    const baseDomain = process.env.BASE_DOMAIN || process.env.DOMAIN_MAIN || 'example.com';
    const countryMap = {
      pl: { name: '🇵🇱 Польша', domain: 'pl.${baseDomain}' },
      fi: { name: '🇫🇮 Финляндия', domain: 'fi.${baseDomain}' },
      nl: { name: '🇳🇱 Нидерланды', domain: 'nl.${baseDomain}' },
    };
    const cinfo = countryMap[String(countryCode || '').toLowerCase()];
    if (!cinfo) {
      return this.sendAdminMenu(chatId, { messageId });
    }

    const cfToken = process.env.CF_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN || '';
    const cfZone = process.env.CF_ZONE_ID || process.env.CLOUDFLARE_ZONE_ID || '';

    try {
      // 1. Resolve target IP dynamically
      const doh = await fetch(`https://cloudflare-dns.com/dns-query?name=${cinfo.domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      });
      const ddata = await doh.json();
      const targetIp = (ddata.Answer && ddata.Answer[0] && ddata.Answer[0].data) || '';
      if (!targetIp) throw new Error(`Could not resolve IP for ${cinfo.domain}`);

      // 2. Update each domain in Cloudflare
      const domains = [baseDomain, 'sub.${baseDomain}', 'edge.${baseDomain}'];
      const updated = [];

      for (const d of domains) {
        // Find record ID
        const sres = await fetch(`https://api.cloudflare.com/client/v4/zones/${cfZone}/dns_records?type=A&name=${d}`, {
          headers: { Authorization: `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
        });
        const sdata = await sres.json();
        if (!sdata.result || !sdata.result[0]) throw new Error(`Record for ${d} not found in Cloudflare`);
        const recId = sdata.result[0].id;

        // Update record with STRICT proxied: false
        const ures = await fetch(`https://api.cloudflare.com/client/v4/zones/${cfZone}/dns_records/${recId}`, {
          method: 'PUT',
          headers: { Authorization: `Bearer ${cfToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'A', name: d, content: targetIp, ttl: 60, proxied: false }),
        });
        const udata = await ures.json();
        if (!udata.success || udata.result?.proxied !== false) {
          throw new Error(`Cloudflare update failed for ${d} or proxied violation`);
        }
        updated.push({ domain: d, ip: targetIp });
      }

      const text = [
        '✅ *АВАРИЙНЫЙ ПЕРЕЕЗД УСПЕШНО ВЫПОЛНЕН!*\n',
        `Кластер переведён на: *${cinfo.name}*`,
        `Системный домен: \`${cinfo.domain}\``,
        `Целевой IP: \`${targetIp}\`\n`,
        'Обновлённые A-записи (Cloudflare DNS-Only ⚪, TTL 60с):',
        ...updated.map(r => `• \`${r.domain}\` -> \`${r.ip}\` (⚪)`),
        '\nТрафик витрины, подписок и моста переведён.',
        'Резервный узел готов к приёму запросов.',
      ].join('\n');

      const markup = kb([
        [['🚨 Управление DR', 'admin:failover']],
        [['« В админ-меню', 'admin:menu']],
      ]);
      await this._renderOrEdit(chatId, text, { replyMarkup: markup, messageId });
    } catch (err) {
      const text = [
        '❌ *ОШИБКА ПЕРЕКЛЮЧЕНИЯ DNS*\n',
        `Не удалось переключить домены на \`${cinfo.domain}\`:`,
        `\`${err.message || err}\`\n`,
        'Проверьте наличие CF_API_TOKEN и CF_ZONE_ID.',
      ].join('\n');

      const markup = kb([
        [['🔄 Попробовать снова', `admin:failover:confirm:${countryCode}`]],
        [['« Назад', 'admin:failover']],
      ]);
      await this._renderOrEdit(chatId, text, { replyMarkup: markup, messageId });
    }
  }

  async showAdminReferrals(chatId, { messageId = null } = {}) {
    const balances = await this.store.listReferralBalances();
    const totalDebt = balances.reduce((s, i) => s + Number(i.balance_rub || 0), 0);
    const totalEarned = balances.reduce((s, i) => s + Number(i.total_earned_rub || 0), 0);
    const totalPaid = balances.reduce((s, i) => s + Number(i.total_paid_rub || 0), 0);
    const payableItems = balances.filter((i) => Number(i.balance_rub || 0) >= REFERRAL_PAYOUT_MIN_RUB);
    const payable = payableItems.reduce((s, i) => s + Number(i.balance_rub || 0), 0);

    const lines = [
      '🤝 Реферальная программа',
      '',
      '📊 Статистика системы:',
      `• 💰 Текущий долг к выплате: ${totalDebt} RUB`,
      `• 💳 Доступно к выплате (≥${REFERRAL_PAYOUT_MIN_RUB} RUB): ${payable} RUB`,
      `• 📈 Начислено всего: ${totalEarned} RUB`,
      `• 💸 Выплачено ранее: ${totalPaid} RUB`,
      `• 👥 Всего партнеров: ${balances.length}`,
      '',
    ];

    if (!balances.length) {
      lines.push('Участников пока нет.');
    } else {
      lines.push('📋 Список партнеров:');
      for (const item of balances.slice(0, 25)) {
        const bal = Number(item.balance_rub || 0);
        const emoji = bal >= REFERRAL_PAYOUT_MIN_RUB ? '🟢' : '⚪';
        lines.push(
          `${emoji} ${ShopBot._displayUser(item)}: долг ${bal} RUB (рефералов: ${Number(item.referred_count || 0)})`
        );
      }
    }

    const rows = payableItems.map((item) => [
      [
        `💳 ${ShopBot._displayUser(item)} • ${Number(item.balance_rub)} RUB`,
        `admin:refpay:${Number(item.id)}`,
        'success',
      ],
    ]);
    rows.push([
      ['🔄 Обновить', 'admin:referrals'],
      ['⬅ В админку', 'admin:menu', 'primary'],
    ]);

    await this._renderOrEdit(chatId, lines.join('\n'), {
      replyMarkup: kb(rows),
      messageId,
    });
  }

  async showAdminRefpay(chatId, referrerId, { messageId = null } = {}) {
    const info = await this.store.getReferralBalance(referrerId);
    if (!info) {
      await this.sendMessage(chatId, 'Партнер не найден.');
      await this.showAdminReferrals(chatId, { messageId });
      return;
    }
    const balance = Number(info.balance_rub || 0);
    const userDisplay = ShopBot._displayUser(info);
    const text = [
      `💳 Выплата партнеру ${userDisplay}`,
      '',
      `• 👤 Партнер: ${userDisplay} (ID ${referrerId})`,
      `• 📈 Накоплено всего: ${Number(info.total_earned_rub || 0)} RUB`,
      `• 💸 Выплачено ранее: ${Number(info.total_paid_rub || 0)} RUB`,
      `• 💰 Текущий долг к выплате: ${balance} RUB`,
      `• 👥 Привлечено рефералов: ${Number(info.referred_count || 0)}`,
      '',
      'Выберите сумму для выплаты или укажите произвольную:',
    ].join('\n');

    const rows = [];
    if (balance > 0) {
      rows.push([[`💰 Вся сумма: ${balance} RUB`, `admin:refpay_exec:${referrerId}:all`, 'success']]);
      const presets = [];
      if (balance >= 500) presets.push(['💳 500 RUB', `admin:refpay_exec:${referrerId}:500`, 'primary']);
      if (balance >= 1000) presets.push(['💳 1000 RUB', `admin:refpay_exec:${referrerId}:1000`, 'primary']);
      if (presets.length) rows.push(presets);
      rows.push([
        ['✍ Своя сумма', `admin:refpay_prompt:${referrerId}`, 'primary'],
        ['⬅ Назад', 'admin:referrals'],
      ]);
    } else {
      rows.push([['⬅ Назад к рефералам', 'admin:referrals', 'primary']]);
    }
    await this._renderOrEdit(chatId, text, { replyMarkup: kb(rows), messageId });
  }

  async executeReferralPayout(chatId, referrerId, user, amountRub = null, { messageId = null } = {}) {
    const info = await this.store.getReferralBalance(referrerId);
    if (!info || Number(info.balance_rub || 0) <= 0) {
      await this.sendMessage(chatId, 'Баланс равен 0 RUB. Выплачивать нечего.');
      await this.showAdminReferrals(chatId, { messageId });
      return;
    }
    const curDebt = Number(info.balance_rub);
    const payout = await this.store.createReferralPayout({
      referrerId,
      actor: `tg:${user?.id}`,
      amountRub,
    });
    if (!payout) {
      await this.sendMessage(chatId, 'Не удалось зафиксировать выплату.');
      return;
    }
    const newBalance = Math.max(curDebt - Number(payout.amount_rub), 0);
    await this.sendMessage(
      chatId,
      `✅ Выплата пользователю ${ShopBot._displayUser(info)} на сумму ${payout.amount_rub} RUB успешно зафиксирована.\n` +
        `Текущий остаток долга: ${newBalance} RUB.`
    );
    if (info.chat_id) {
      try {
        await this.sendMessage(
          info.chat_id,
          `🎉 Вам выплачено реферальное вознаграждение: ${payout.amount_rub} RUB!\nОстаток на балансе: ${newBalance} RUB.`
        );
      } catch (_) {
        // ignore
      }
    }
    await this.showAdminReferrals(chatId);
  }

  async notifyAdminsReferralThreshold(referrerId, balance) {
    const ref = await this.store.getReferralBalance(referrerId);
    const userInfo = ref ? ShopBot._displayUser(ref) : `ID ${referrerId}`;
    const text = `🔔 Реферер ${userInfo} набрал сумму для выплаты (${balance} RUB)!`;
    const markup = kb([[['💳 Выплатить', `admin:refpay:${referrerId}`, 'success']]]);
    for (const adminId of this.settings.adminUserIds || []) {
      try {
        await this.sendMessage(adminId, text, { replyMarkup: markup });
      } catch (_) {
        // ignore
      }
    }
  }

  async handleWarpSubUrl(chatId, text, session) {
    const raw = String(text || '').trim();
    const m = raw.match(/\/json(?:-[a-zA-Z0-9]+)?\/([A-Za-z0-9]{6,32})/);
    const subId = m ? m[1] : /^[A-Za-z0-9]{6,32}$/.test(raw) ? raw : '';
    if (!subId) {
      await this.sendMessage(
        chatId,
        `Не распознал id подписки. Пришли ссылку вида ${this.settings.subscriptionBaseUrl}/<id> или сам id.`
      );
      return;
    }
    const context = ShopBot._contextFromSession(session);
    const targetServer = String(context.server_code || context.target_server || 'nl')
      .toLowerCase()
      .trim();

    try {
      const warpRes = await this.provisioner.buildWarpConfig(subId, targetServer);
      const confText = warpRes.conf_text || warpRes.conf || warpRes.result?.conf || '';
      const confBytes = new TextEncoder().encode(String(confText));
      const filename = `warp-${targetServer.toUpperCase()}-${subId}.conf`;
      await api.sendDocument({
        chat_id: chatId,
        document: new InputFile(confBytes, filename, 'text/plain'),
        caption:
          warpRes.caption ||
          `Warp-конфиг (${targetServer.toUpperCase()}).\nПодписка: ${subId}\nЛимит: 500 ГБ / 30 дней.`,
      });
    } catch (err) {
      await this.sendMessage(chatId, `Не удалось создать warp-конфиг: ${err.message || err}`);
    }
    await this.sendAdminMenu(chatId);
  }

  // --- Обработка команды /start ---
  async handlePublicStart(chatId, startArg, user = null) {
    const session = await this.store.getSession(chatId);
    if (startArg === PUBLIC_ACCESS_START_CODE) {
      const context = ShopBot._contextFromSession(session);
      context.public_access = true;
      await this.store.setSession(chatId, 'public', 'menu', context);
      await this.showPublicMenu(
        chatId,
        'Ссылка доступа активирована. Можно выбрать тариф, пробную неделю или реферальную программу.',
        { user }
      );
      return;
    }
    if (['referral', 'ref', 'referrals'].includes(startArg)) {
      await this.showPublicReferral(chatId, user || {});
      return;
    }
    if (startArg.startsWith('claim_')) {
      const payload = startArg.slice('claim_'.length);
      let orderPublicId = '';
      let token = '';
      if (payload.startsWith('ord_')) {
        const rest = payload.slice(4);
        const idx = rest.indexOf('_');
        if (idx !== -1) {
          orderPublicId = `ord_${rest.slice(0, idx)}`;
          token = rest.slice(idx + 1);
        }
      } else {
        const idx = payload.lastIndexOf('_');
        if (idx !== -1) {
          orderPublicId = payload.slice(0, idx);
          token = payload.slice(idx + 1);
        }
      }
      if (!orderPublicId || !token) {
        await this.showPublicMenu(chatId, 'Ссылка привязки недействительна.', { user });
        return;
      }
      const order = await this.store.getOrderByWebToken(orderPublicId, token);
      if (!order || order.status !== 'delivered' || !order.provisioned_profile_id) {
        await this.showPublicMenu(
          chatId,
          'Заказ с сайта ещё не подтверждён или ссылка недействительна.',
          { user }
        );
        return;
      }
      const profile = await this.store.getProfileForOrder(orderPublicId);
      if (!profile || profile.status === 'deleted') {
        await this.showPublicMenu(chatId, 'Профиль по этому заказу уже недоступен.', { user });
        return;
      }
      await this.store.linkProfileOwner({
        profilePublicId: String(profile.public_id),
        userId: user?.id || chatId,
        chatId,
        sourceOrderPublicId: orderPublicId,
      });
      const result = await this._recoverSubscriptionForOrder(order);
      await this._sendPublicSubscription(chatId, result.subscription_url, {
        prefix: 'Личный кабинет • Подписка с сайта привязана к Telegram!',
      });
      return;
    }
    if (startArg.startsWith('ref_')) {
      const [status, attribution] = await this.store.attachReferral({
        code: startArg,
        referredUserId: chatId,
        referredChatId: chatId,
      });
      const context = ShopBot._contextFromSession(session);
      if (status === 'created' && attribution) {
        context.referrer_id = attribution.referrer_id;
        context.referral_discount = REFERRAL_INVITEE_DISCOUNT_PERCENT;
        await this.store.setSession(chatId, 'public', 'menu', context);
        if (attribution.referrer_chat_id) {
          const uname = user?.username ? `@${user.username}` : user?.first_name || `ID ${chatId}`;
          try {
            await this.sendMessage(
              attribution.referrer_chat_id,
              `🤝 По вашей реферальной ссылке зарегистрировался новый пользователь (${uname})! Когда он оплатит подписку, вы получите 10% комиссии.`
            );
          } catch (_) {
            // ignore
          }
        }
        await this.showPublicMenu(
          chatId,
          '🎁 Реферальная ссылка активирована! Вам доступна скидка 10% на первую подписку + 7 дней бесплатного пробного периода.',
          { user }
        );
        return;
      }
      if (status === 'exists') {
        await this.showPublicMenu(chatId, 'Вы уже прикреплены к реферальной программе. Можно продолжать.', {
          user,
        });
        return;
      }
      if (status === 'already_customer') {
        await this.showPublicMenu(
          chatId,
          'Реферальный бонус доступен только для новых пользователей. Вы уже являетесь нашим клиентом!',
          { user }
        );
        return;
      }
      if (status === 'self') {
        await this.showPublicMenu(chatId, 'Свою же реферальную ссылку использовать нельзя.', { user });
        return;
      }
      await this.showPublicMenu(chatId, 'Реферальная ссылка недействительна.', { user });
      return;
    }
    if (startArg) {
      const invite = await this.store.findValidInvite(startArg);
      if (!invite) {
        await this.sendMessage(chatId, 'Ссылка-приглашение недействительна или уже использована.');
        return;
      }
      const context = ShopBot._contextFromSession(session);
      context.invite_id = invite.id;
      await this.store.setSession(chatId, 'public', 'menu', context);
      await this.showPublicMenu(chatId, 'Персональная ссылка активирована. Можно продолжать.', { user });
      return;
    }

    const activeOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
    if (activeOrder) {
      await this._sendExistingPublicOrder(chatId, activeOrder, { prefix: 'Возвращаю текущий заказ.' });
      return;
    }
    await this.showPublicMenu(chatId, null, { user });
  }

  // --- Разделы доступа и подключения ---
  async showPublicAccessCompare(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    await this._renderOrEdit(
      chatId,
      [
        'Что выбрать?',
        '',
        'Если не хотите разбираться в деталях, начните с рекомендуемого доступа.',
        '',
        'Рекомендуемый доступ:',
        '• основной вариант по умолчанию',
        '• обычно проще как первый выбор',
        '• лучше подходит как стартовая точка',
        '',
        'Гибкий доступ:',
        '• альтернативный способ подключения',
        '• полезен, если нужен запасной вариант на конкретной сети',
        '',
        'Универсальный доступ:',
        '• внутри сразу TCP+REALITY и XHTTP',
        '• приложения с поддержкой балансировки могут быстрее переключаться на живой путь',
      ].join('\n'),
      {
        replyMarkup: kb([
          [['Выбрать доступ', 'public:access']],
          [['Для продвинутых', 'public:access_advanced']],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async showPublicAccessAdvanced(chatId, { messageId = null } = {}) {
    await this._mergeSessionState(chatId, 'public', 'menu', null, {
      dropKeys: ['pending_promo', 'pending_promo_id'],
    });
    await this._renderOrEdit(
      chatId,
      [
        'Для продвинутых',
        '',
        'Рекомендуемый доступ = TCP+REALITY',
        'Гибкий доступ = XHTTP',
        'Универсальный доступ = TCP+REALITY + XHTTP в одной подписке',
        '',
        'Все варианты выдают персональную ссылку через один и тот же поток заказа и поддержки.',
      ].join('\n'),
      {
        replyMarkup: kb([
          [['Выбрать доступ', 'public:access']],
          [['Что выбрать?', 'public:access_compare']],
          [['Назад в меню', 'public:menu']],
        ]),
        messageId,
      }
    );
  }

  async showPublicConnectPlatform(chatId, subscriptionId) {
    const subscriptionUrl = this._subscriptionUrlFromId(subscriptionId);
    const setupUrl = ShopBot._subscriptionSetupUrl(subscriptionUrl);
    await this.sendMessage(
      chatId,
      [
        'Подключение',
        '',
        'Откройте страницу подключения. Там можно выбрать устройство и приложение, а Happ будет предложен первым, если подходит.',
        'Если автоматическое добавление не сработает, на этой же странице есть копирование ссылки.',
      ].join('\n'),
      {
        replyMarkup: kb([
          [['Подключить', setupUrl, 'success']],
          [{ text: 'Скопировать ссылку', copy_text: subscriptionUrl, style: 'primary' }],
          [
            ['Как подключить', 'public:help'],
            ['Поддержка', 'public:support', 'primary'],
          ],
        ]),
        protectContent: true,
      }
    );
  }

  // --- Управление профилями в админке ---
  async showAdminProfile(chatId, profilePublicId) {
    const profile = await this.store.getProfile(profilePublicId);
    if (!profile) {
      await this.sendMessage(chatId, `Профиль ${profilePublicId} не найден.`);
      return;
    }
    const found = await this.provisioner.findClientByEmail(String(profile.xui_email));
    const traffic = (await this.provisioner.getClientTraffic(String(profile.xui_email))) || {};
    const client = found?.client || {};
    const enabled = Boolean(client.enable ?? traffic.enable ?? false);
    const limitIp = client.limitIp ?? profile.device_limit ?? 0;
    const owner = await this.store.getProfileOwner(profilePublicId);
    const usedBytes = Number(traffic.up || 0) + Number(traffic.down || 0);

    const lines = [
      `Профиль \`${profilePublicId}\``,
      '',
      `Email: \`${profile.xui_email}\``,
      `Транспорт: ${ShopBot.transportLabel(String(profile.transport))}`,
      `Статус в базе: ${profile.status}`,
      `Статус Xray: ${enabled ? 'включён' : 'отключён'}`,
      `Лимит устройств: ${ShopBot.deviceLimitLabel(limitIp)}`,
      `Истекает: ${ShopBot.formatTs(profile.expires_at)}`,
      `Трафик: ${ShopBot.formatGb(usedBytes)}`,
      `Последний онлайн: ${ShopBot.formatXuiTs(traffic.last_online)}`,
    ];
    if (owner) {
      lines.push('', `Владелец: tg:${owner.user_id}`, `Chat: \`${owner.chat_id}\``);
    } else {
      lines.push('', 'Владелец в боте не привязан.');
    }

    const buttons = [];
    if (found && profile.status !== 'deleted') {
      if (enabled) {
        buttons.push([['Отключить профиль', `admin:profile_disable:${profilePublicId}`, 'danger']]);
      } else {
        buttons.push([['Включить профиль', `admin:profile_enable:${profilePublicId}`, 'success']]);
      }
    }
    if (owner) {
      buttons.push([['Отправить предупреждение', `admin:profile_warn:${profilePublicId}`, 'primary']]);
    }
    buttons.push([['Назад к трафику', 'admin:traffic_top']], [['Назад в админ-меню', 'admin:menu']]);
    await this.sendMessage(chatId, lines.join('\n'), { replyMarkup: kb(buttons) });
  }

  async setAdminProfileEnabled(chatId, profilePublicId, enabled, user) {
    const result = await this.provisioner.setProfileEnabled(profilePublicId, enabled);
    await this.store.recordAdminAction({
      actionType: enabled ? 'profile_enable' : 'profile_disable',
      targetType: 'profile',
      targetPublicId: profilePublicId,
      actor: `tg:${user?.id}`,
      meta: { xui_email: result.xui_email, inbound_id: result.inbound_id },
    });
    await this.sendMessage(
      chatId,
      `Профиль ${profilePublicId} ${enabled ? 'включён' : 'отключён'}.`
    );
    await this.showAdminProfile(chatId, profilePublicId);
  }

  async warnAdminProfileOwner(chatId, profilePublicId, user) {
    const profile = await this.store.getProfile(profilePublicId);
    const owner = await this.store.getProfileOwner(profilePublicId);
    if (!profile || !owner) {
      await this.sendMessage(chatId, 'Не нашёл привязанного владельца этого профиля.');
      return;
    }
    const warningText =
      'По вашей подписке замечена необычная нагрузка или слишком много одновременных подключений. ' +
      'Пожалуйста, используйте доступ только в рамках выбранного тарифа. ' +
      `Если это ошибка, напишите в поддержку: ${this.settings.supportTgUrl}`;
    await this.sendMessage(owner.chat_id, warningText);
    await this.store.recordAdminAction({
      actionType: 'profile_warning',
      targetType: 'profile',
      targetPublicId: profilePublicId,
      actor: `tg:${user?.id}`,
      meta: { xui_email: profile.xui_email, owner_chat_id: owner.chat_id },
    });
    await this.sendMessage(chatId, `Предупреждение отправлено владельцу профиля ${profilePublicId}.`);
  }

  // --- Главный роутер входящих текстовых сообщений ---
  async handleMessage(message) {
    const chatId = message.chat.id;
    const user = message.from || {};
    await this.store?.upsertTelegramUser?.({ user, chatId });

    const text = String(message.text || '').trim();
    const replyToMessage = message.reply_to_message || {};
    const rawCmd = text.startsWith('/') ? text.split(/\s+/)[0].toLowerCase() : '';
    const command = rawCmd ? rawCmd.split('@')[0] : '';
    const isAdminUser = this.isAdmin(user) || this.isAdmin(chatId);

    if (text.startsWith('/start')) {
      const parts = text.split(/\s+/);
      const startArg = parts.length > 1 ? parts.slice(1).join(' ').trim() : '';
      if (isAdminUser && !startArg) {
        const session = await this.store.getSession(chatId);
        if (session && session.scope === 'public') {
          await this.handlePublicStart(chatId, startArg, user);
          return;
        }
        await this.sendAdminMenu(chatId);
        return;
      }
      await this.handlePublicStart(chatId, startArg, user);
      return;
    }

    if (['/cabinet', '/lk'].includes(command)) {
      await this.showPublicCabinet(chatId, user);
      return;
    }
    if (['/referral', '/ref', '/partner'].includes(command)) {
      await this.showPublicReferral(chatId, user);
      return;
    }
    if (command === '/client' && isAdminUser) {
      await this._mergeSessionState(chatId, 'public', 'menu');
      await this.handlePublicStart(chatId, '', user);
      return;
    }
    if (text === '/admin' && isAdminUser) {
      await this.sendAdminMenu(chatId);
      return;
    }
    if (command === '/prices') {
      await this.showPublicAccessMenu(chatId);
      return;
    }
    if (command === '/help') {
      await this.showPublicHelp(chatId);
      return;
    }
    if (command === '/faq') {
      await this.showPublicFaq(chatId);
      return;
    }
    if (command === '/rules') {
      await this.showPublicRulesMenu(chatId);
      return;
    }
    if (command === '/support') {
      await this.showPublicSupport(chatId);
      return;
    }
    if (command === '/pay') {
      const activeOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: false });
      if (activeOrder) {
        const msg = await this._waitingPaymentMessage(activeOrder);
        const markup = await this._publicWaitingPaymentMarkup(
          String(activeOrder.public_id),
          activeOrder
        );
        await this.sendMessage(chatId, msg, { replyMarkup: markup });
      } else {
        await this.showPublicAccessMenu(chatId);
      }
      return;
    }

    const session = await this.store.getSession(chatId);
    if (!session) {
      if (isAdminUser) {
        await this.sendAdminMenu(chatId);
      } else {
        await this.showPublicMenu(chatId, null, { user });
      }
      return;
    }

    if (session.scope === 'public' && session.state === 'await_renewal_subscription_url') {
      await this.handleRenewalSubscriptionUrlInput(chatId, text, session, user);
      return;
    }
    if (session.scope === 'public' && session.state === 'await_promo_code') {
      await this.handlePromoInput(chatId, text, session);
      return;
    }
    if (session.scope === 'admin' && session.state === 'admin_wait_promo_months') {
      const months = parseInt(text.replace(',', '.'), 10);
      if (!Number.isFinite(months) || months <= 0 || months > 120) {
        await this.sendMessage(chatId, 'Укажите срок от 1 до 120 месяцев целым числом.');
        return;
      }
      const context = ShopBot._contextFromSession(session);
      context.admin = true;
      context.duration_days = months * 30;
      context.duration_months = months;
      await this.store.setSession(chatId, 'admin', 'admin_promo_price', context);
      await this._sendAdminPromoPricePrompt(chatId, context);
      return;
    }
    if (session.scope === 'admin' && session.state === 'admin_wait_promo_price') {
      const price = parseInt(text.replace(/\s+/g, ''), 10);
      if (!Number.isFinite(price) || price < 0 || price > 1000000) {
        await this.sendMessage(chatId, 'Укажите цену от 0 до 1000000 RUB целым числом.');
        return;
      }
      const context = ShopBot._contextFromSession(session);
      context.admin = true;
      context.discount_percent = 0;
      context.fixed_price_rub = price;
      await this.store.setSession(chatId, 'admin', 'admin_promo_mode', context);
      await this._sendAdminPromoModePrompt(chatId, context);
      return;
    }
    if (session.scope === 'admin' && session.state === 'admin_wait_family_label') {
      const label = text.trim();
      if (!label) {
        await this.sendMessage(chatId, 'Нужна непустая подпись, например babuska1.');
        return;
      }
      const context = ShopBot._contextFromSession(session);
      const [code] = await this.store.createPromoCode({
        promoType: 'fixed',
        transport: context.transport,
        durationDays: context.duration_days,
        durationMonths: context.duration_months,
        discountPercent: context.discount_percent || 0,
        fixedPriceRub: context.fixed_price_rub,
        deviceLimit: Number(context.device_limit ?? this.settings.defaultDeviceLimit),
        profileMode: 'family',
        familyLabel: label,
        maxUses: 1,
      });
      await this.store.setSession(chatId, 'admin', 'menu', { admin: true });
      await this.sendMessage(
        chatId,
        `Промокод создан:\n${code}\n\nТип: готовый доступ\nПодпись: ${label}`
      );
      return;
    }
    if (session.scope === 'admin' && session.state === 'admin_wait_warp_sub_url') {
      await this.handleWarpSubUrl(chatId, text, session);
      return;
    }
    if (session.scope === 'admin' && session.state === 'admin_wait_refpay_amount') {
      const context = ShopBot._contextFromSession(session);
      const referrerId = Number(context.refpay_referrer_id || 0);
      const cleaned = text.replace(/[\sRUBrub₽]/g, '');
      const amount = parseInt(cleaned, 10);
      if (!Number.isFinite(amount) || amount <= 0) {
        await this.sendMessage(chatId, '⚠️ Введите корректную сумму выплаты больше 0.');
        return;
      }
      await this._mergeSessionState(chatId, 'admin', 'menu', {}, { dropKeys: ['refpay_referrer_id'] });
      await this.executeReferralPayout(chatId, referrerId, user, amount);
      return;
    }

    if (isAdminUser && text && replyToMessage.message_id != null) {
      const order = await this.store.getOrderByManagerMessage(chatId, Number(replyToMessage.message_id));
      if (order && order.status === 'waiting_payment' && order.customer_chat_id) {
        const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
        await this.sendMessage(
          order.customer_chat_id,
          `Реквизиты для оплаты заказа \`${order.public_id}\`:\n${text}\n\nПосле перевода нажмите «Оплачено».`,
          { replyMarkup: markup, protectContent: true }
        );
        await this.sendMessage(chatId, `Реквизиты по заказу ${order.public_id} отправлены клиенту.`);
        return;
      }
    }

    await this.sendMessage(chatId, 'Команда не распознана. Используйте кнопки в чате.');
  }

  async _sendAdminPromoPricePrompt(chatId, context) {
    const basePrice = this.basePriceForDuration(String(context.transport), Number(context.duration_days), {
      deviceLimit: Number(context.device_limit ?? this.settings.defaultDeviceLimit),
    });
    const durationLabel = ShopBot.promoDurationLabel(context);
    await this.sendMessage(
      chatId,
      `Выберите цену промокода.\n\nСрок: ${durationLabel}\nОбычная цена: ${basePrice} RUB`,
      {
        replyMarkup: kb([
          [[`Обычная цена • ${basePrice} RUB`, 'admin:promo_price:regular', 'success']],
          [['Ввести цену вручную', 'admin:promo_price:manual', 'primary']],
          [['Бесплатно', 'admin:promo_price:free']],
          [
            ['Скидка 25%', 'admin:promo_discount:25'],
            ['Скидка 50%', 'admin:promo_discount:50'],
          ],
          [
            ['Скидка 75%', 'admin:promo_discount:75'],
            ['Скидка 100%', 'admin:promo_discount:100'],
          ],
        ]),
      }
    );
  }

  async _sendAdminPromoModePrompt(chatId, context) {
    const basePrice = this.basePriceForDuration(String(context.transport), Number(context.duration_days), {
      deviceLimit: Number(context.device_limit ?? this.settings.defaultDeviceLimit),
    });
    const priceLabel = ShopBot.fixedPromoPriceLabel(context, basePrice);
    await this.sendMessage(
      chatId,
      `Это анонимный или семейный промокод?\n\nСрок: ${ShopBot.promoDurationLabel(context)}\nЦена: ${priceLabel}`,
      {
        replyMarkup: kb([
          [['Анонимный', 'admin:promo_mode:anonymous']],
          [['Семейный', 'admin:promo_mode:family']],
        ]),
      }
    );
  }

  // --- Главный роутер Callback Query ---
  async handleCallback(callback) {
    const callbackId = callback.id;
    const user = callback.from || {};
    const data = String(callback.data || '');
    const chat = callback.message?.chat || {};
    const chatId = chat.id;
    const messageId = callback.message?.message_id;
    if (chatId != null) {
      await this.store?.upsertTelegramUser?.({ user, chatId });
    }

    try {
      if (data === 'admin:menu' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.sendAdminMenu(chatId, { messageId });
        return;
      }

      if (data === 'public:menu' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicMenu(chatId, null, { messageId, user });
        return;
      }

      if (data === 'public:cabinet' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicCabinet(chatId, user, { messageId });
        return;
      }

      if (data === 'public:access' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicAccessMenu(chatId, { messageId });
        return;
      }

      if (data === 'public:access_compare' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicAccessCompare(chatId, { messageId });
        return;
      }

      if (data === 'public:access_advanced' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicAccessAdvanced(chatId, { messageId });
        return;
      }

      if (data.startsWith('public:connect:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const subscriptionId = data.split(':').slice(2).join(':');
        await this.showPublicConnectPlatform(chatId, subscriptionId);
        return;
      }

      if (data.startsWith('public:connect_platform:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        const subscriptionId = parts.slice(3).join(':');
        await this.showPublicConnectPlatform(chatId, subscriptionId);
        return;
      }

      if (data === 'public:accept_terms' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        try {
          await this.store.recordAdminAction({
            actionType: 'accept_public_terms',
            targetType: 'telegram_user',
            targetPublicId: String(user?.id || chatId),
            actor: `tg:${user?.id || chatId}`,
            meta: { version: '2026-04-26', chat_id: chatId },
          });
        } catch (e) {
          console.error('Failed to record terms acceptance:', e);
        }
        await this.showPublicMenu(chatId, null, { messageId, user });
        return;
      }

      if (data.startsWith('public:buy_devices:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const limit = parseInt(data.split(':').pop(), 10);
        await this.showPublicBuyDuration(chatId, limit, { messageId });
        return;
      }

      if (data.startsWith('public:buy_duration:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const durationDays = parseInt(data.split(':').pop(), 10);
        const session = (await this.store.getSession(chatId)) || {
          scope: 'public',
          state: 'buy_devices',
          context_json: {},
        };
        const context = ShopBot._contextFromSession(session);
        context.buy_duration_days = durationDays;
        context.buy_mode = 'tcp';
        await this.store.setSession(chatId, 'public', 'buy_duration', context);
        await this.showPublicBuyConfirm(chatId, 'tcp', { messageId });
        return;
      }

      if (data === 'public:buy_confirm' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const session = (await this.store.getSession(chatId)) || {
          scope: 'public',
          state: 'buy_confirm',
          context_json: {},
        };
        const context = ShopBot._contextFromSession(session);
        const offer = this.offers[this._purchaseOfferCode(context)];
        if (!offer) {
          await this.sendMessage(chatId, 'Не удалось собрать тариф. Попробуйте выбрать заново.');
          await this.showPublicAccessMenu(chatId);
          return;
        }
        await this.createStandardOrder(chatId, offer);
        return;
      }

      if (data.startsWith('public:buy_back:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const target = data.split(':').pop();
        const session = await this.store.getSession(chatId);
        const context = ShopBot._contextFromSession(session);
        if (target === 'duration' && context.buy_device_limit) {
          await this.showPublicBuyDuration(chatId, Number(context.buy_device_limit), { messageId });
          return;
        }
        await this.showPublicAccessMenu(chatId, { messageId });
        return;
      }

      if (data.startsWith('public:buy:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const offerCode = data.split(':').pop();
        const offer = this.offers[offerCode];
        if (!offer) {
          await this.sendMessage(chatId, 'Вариант доступа не найден.');
          return;
        }
        if (!(await this._publicHasPurchaseAccess(chatId))) {
          await this._sendAccessLocked(chatId);
          return;
        }
        await this.createStandardOrder(chatId, offer);
        return;
      }

      if (data === 'public:renew' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicRenewal(chatId, user, { messageId });
        return;
      }

      if (data === 'public:renew_other' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.promptPublicRenewalLink(chatId, { messageId });
        return;
      }

      if (data === 'public:renew_promo' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this._sendPublicPromoPrompt(chatId, {
          prefix: 'Введите скидочный промокод для продления.',
          messageId,
          promoReturn: 'renewal',
        });
        return;
      }

      if (data.startsWith('public:renew_devices:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicRenewDevices(chatId, data.split(':')[2], { messageId });
        return;
      }

      if (data.startsWith('public:renew_duration:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        await this.showPublicRenewDuration(chatId, parts[2], parseInt(parts[3], 10), { messageId });
        return;
      }

      if (data.startsWith('public:renew_preview:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        await this.showPublicRenewConfirm(chatId, parts[2], {
          deviceLimit: parseInt(parts[3], 10),
          durationDays: parseInt(parts[4], 10),
          messageId,
        });
        return;
      }

      if (data.startsWith('public:renew_confirm:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        await this.createRenewalOrder(chatId, user, parts[2], parseInt(parts[3] || '30', 10), {
          deviceLimit: parts[4] ? parseInt(parts[4], 10) : null,
        });
        return;
      }

      if (data.startsWith('public:upgrade_devices:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicUpgradeDevices(chatId, data.split(':')[2], { messageId });
        return;
      }

      if (data.startsWith('public:upgrade_preview:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        await this.showPublicUpgradeConfirm(chatId, parts[2], parseInt(parts[3], 10), { messageId });
        return;
      }

      if (data.startsWith('public:upgrade_confirm:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const parts = data.split(':');
        await this.createRenewalOrder(chatId, user, parts[2], 0, {
          deviceLimit: parseInt(parts[3], 10),
          upgradeOnly: true,
        });
        return;
      }

      if (data === 'public:trial' && chatId != null) {
        await this.answerCallbackQuery(callbackId, 'Создаю пробный доступ');
        await this.createPublicTrial(chatId, user, { messageId });
        return;
      }

      if (data === 'public:referral' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicReferral(chatId, user, { messageId });
        return;
      }

      if (data === 'public:referral_join' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.joinPublicReferral(chatId, user, { messageId });
        return;
      }

      if (data === 'public:help' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicHelp(chatId, { messageId });
        return;
      }

      if (data === 'public:faq' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicFaq(chatId, { messageId });
        return;
      }

      if (data === 'public:rules' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicRulesMenu(chatId, { messageId });
        return;
      }

      if (data.startsWith('public:rules:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicRulesSection(chatId, data.split(':').pop(), { messageId });
        return;
      }

      if (data === 'public:support' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        await this.showPublicSupport(chatId, { messageId });
        return;
      }

      if (data === 'public:promo' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const waitingOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
        if (waitingOrder && waitingOrder.status === 'waiting_payment') {
          await this.sendMessage(
            chatId,
            `У вас уже есть неоплаченный заказ \`${waitingOrder.public_id}\`.\nЧтобы ввести промокод, сначала нужно отменить текущий заказ.`,
            {
              replyMarkup: kb([
                [
                  [
                    'Отменить и ввести промокод',
                    `public:promo_switch_confirm:${waitingOrder.public_id}`,
                    'danger',
                  ],
                ],
                [['Оставить текущий заказ', `public:promo_switch_keep:${waitingOrder.public_id}`]],
              ]),
            }
          );
          return;
        }
        await this._sendPublicPromoPrompt(chatId, { messageId });
        return;
      }

      if (data.startsWith('public:promo_switch:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const waitingOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
        if (waitingOrder && waitingOrder.status === 'waiting_payment') {
          await this.sendMessage(
            chatId,
            `У вас уже есть неоплаченный заказ \`${waitingOrder.public_id}\`.\nЧтобы ввести промокод, сначала нужно отменить текущий заказ.`,
            {
              replyMarkup: kb([
                [
                  [
                    'Отменить и ввести промокод',
                    `public:promo_switch_confirm:${waitingOrder.public_id}`,
                    'danger',
                  ],
                ],
                [['Оставить текущий заказ', `public:promo_switch_keep:${waitingOrder.public_id}`]],
              ]),
            }
          );
          return;
        }
        await this._sendPublicPromoPrompt(chatId, { messageId });
        return;
      }

      if (data.startsWith('public:promo_switch_confirm:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const cancelled = await this.store.cancelOpenOrdersForChat(chatId);
        await this._sendPublicPromoPrompt(chatId, {
          prefix: cancelled.length
            ? 'Все открытые неоплаченные заказы этого чата закрыты.'
            : 'Открытых неоплаченных заказов уже не было.',
          messageId,
        });
        return;
      }

      if (data.startsWith('public:promo_switch_keep:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const waitingOrder = await this._freshActiveOrderForChat(chatId, { notifyUser: true });
        if (waitingOrder) {
          await this._sendExistingPublicOrder(chatId, waitingOrder, { prefix: 'Оставляю текущий заказ.' });
          return;
        }
        await this.showPublicMenu(chatId, 'Открытых неоплаченных заказов уже нет.', { messageId });
        return;
      }

      if (data.startsWith('public:payment_sent:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const orderPublicId = data.split(':').pop();
        const order = await this.store.getOrder(orderPublicId);
        if (!order || order.status !== 'waiting_payment') {
          await this.sendMessage(chatId, 'Этот заказ уже не ждёт оплаты.');
          return;
        }
        await this.notifyAdminsPaymentReported(order, user);
        const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
        await this.sendMessage(
          chatId,
          'Спасибо, уведомление об оплате отправлено. Я проверю поступление и подтвержу заказ.',
          { replyMarkup: markup }
        );
        return;
      }

      if (data.startsWith('public:check_payment:') && chatId != null) {
        await this.answerCallbackQuery(callbackId, 'Проверяю статус платежа...');
        const orderPublicId = data.split(':').pop();
        const order = await this.store.getOrder(orderPublicId);
        if (!order || String(order.customer_chat_id || '') !== String(chatId)) {
          await this.sendMessage(chatId, 'Заказ не найден или уже завершён.');
          return;
        }
        if (order.status === 'delivered') {
          await this.sendMessage(chatId, 'Оплата уже подтверждена! Данные доступа отправлены выше.');
          return;
        }
        const meta = { ...(order.meta_json || {}) };
        const txId = String(meta.platega_transaction_id || '').trim();
        if (txId && this.platega.isConfigured) {
          try {
            const txStatus = await this.platega.getTransactionStatus(txId, true);
            const status = String(txStatus.status || '').trim().toUpperCase();
            if (status === 'CONFIRMED') {
              meta.platega_confirmed_at = nowTs();
              await this.store.updateOrderMeta(String(order.public_id), meta);
              await this.completeOrder(order, 'user_check_payment');
              await this.sendMessage(chatId, '✅ Оплата успешно подтверждена! Доступ активирован.');
              return;
            }
          } catch (err) {
            console.error(`Failed Platega status check for ${orderPublicId}:`, err);
          }
        }
        const markup = await this._publicWaitingPaymentMarkup(String(order.public_id), order);
        await this.sendMessage(
          chatId,
          'Платёж ещё обрабатывается платёжным шлюзом. Как только банк подтвердит зачисление, бот моментально выдаст вам доступ.',
          { replyMarkup: markup }
        );
        return;
      }

      if (data.startsWith('public:cancel_waiting:') && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const cancelled = await this.store.cancelOpenOrdersForChat(chatId);
        await this.showPublicMenu(
          chatId,
          cancelled.length
            ? 'Неоплаченный заказ отменён. Можно выбрать новый вариант.'
            : 'Открытых неоплаченных заказов уже нет.',
          {
            dropKeys: [ACTION_GUARD_KEY, 'order_public_id', 'pending_promo', 'pending_promo_id'],
            messageId,
          }
        );
        return;
      }

      if (data === 'public:family_accept' && chatId != null) {
        await this.answerCallbackQuery(callbackId);
        const session = await this.store.getSession(chatId);
        const promo = session?.context_json?.pending_promo;
        if (promo) {
          await this.createPromoOrder(chatId, promo, session.context_json);
        }
        return;
      }

      if (data === 'public:family_decline' && chatId != null) {
        await this.answerCallbackQuery(callbackId, 'Промокод не потрачен');
        const session = await this.store.getSession(chatId);
        const promo = session?.context_json?.pending_promo;
        if (promo) {
          for (const adminChat of await this.store.listChatIdsByScope('admin')) {
            await this.sendMessage(
              adminChat,
              `Пользователь отказался от семейного промокода \`${promo.family_label}\` из-за приватности. Код не сожжён.`
            );
          }
        }
        await this.showPublicMenu(
          chatId,
          'Промокод не потрачен. Можно вернуться в витрину и выбрать другой сценарий.'
        );
        return;
      }

      // --- АДМИН-КОЛБЭКИ ---

      if (data === 'admin:failover' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.showAdminFailover(chatId, { messageId });
        return;
      }

      if (data.startsWith('admin:failover:confirm:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const country = data.split(':').pop();
        await this.showAdminFailoverConfirm(chatId, country, { messageId });
        return;
      }

      if (data.startsWith('admin:failover:apply:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, { text: 'Выполняем переключение DNS...' });
        const country = data.split(':').pop();
        await this.executeAdminFailover(chatId, country, { messageId });
        return;
      }

      if (data === 'admin:server' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const statusText = await this.provisioner.getServerStatusText();
        await this.sendMessage(chatId, statusText, {
          replyMarkup: kb([
            [['Обновить', 'admin:server', 'primary']],
            [['Топ трафика', 'admin:traffic_top', 'primary']],
            [['Назад в админ-меню', 'admin:menu']],
          ]),
        });
        return;
      }

      if (data === 'admin:traffic_top' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const rows = await this.provisioner.listClientTraffic(20);
        const lines = ['Топ профилей по суммарному трафику', ''];
        const buttons = [];
        for (let i = 0; i < rows.length; i++) {
          const t = rows[i];
          const email = String(t.email || '');
          const used = Number(t.up || 0) + Number(t.down || 0);
          const enabled = Number(t.enable || 0) ? 'вкл' : 'выкл';
          lines.push(
            `${i + 1}. \`${email}\`: ${ShopBot.formatGb(used)}, ${enabled}, последний раз: ${ShopBot.formatXuiTs(t.last_online)}`
          );
          const prof = await this.store.getProfileByXuiEmail(email);
          if (prof) {
            buttons.push([[email.slice(0, 24), `admin:profile:${prof.public_id}`]]);
          }
        }
        if (!rows.length) lines.push('Данных по трафику пока нет.');
        buttons.push(
          [['Обновить', 'admin:traffic_top', 'primary']],
          [['Состояние сервера', 'admin:server']],
          [['Назад в админ-меню', 'admin:menu']]
        );
        await this.sendMessage(chatId, lines.join('\n'), { replyMarkup: kb(buttons) });
        return;
      }

      if (data === 'admin:referrals' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.showAdminReferrals(chatId, { messageId });
        return;
      }

      if (data.startsWith('admin:refpay:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const refId = parseInt(data.split(':').pop(), 10);
        await this.showAdminRefpay(chatId, refId, { messageId });
        return;
      }

      if (data.startsWith('admin:refpay_exec:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Выполняю выплату...');
        const parts = data.split(':');
        const refId = parseInt(parts[2], 10);
        const amt = parts[3] === 'all' ? null : parseInt(parts[3], 10);
        await this.executeReferralPayout(chatId, refId, user, amt, { messageId });
        return;
      }

      if (data.startsWith('admin:refpay_prompt:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const refId = parseInt(data.split(':').pop(), 10);
        const info = await this.store.getReferralBalance(refId);
        const curDebt = Number(info?.balance_rub || 0);
        await this._mergeSessionState(
          chatId,
          'admin',
          'admin_wait_refpay_amount',
          { refpay_referrer_id: refId },
          { dropKeys: [ACTION_GUARD_KEY] }
        );
        await this._renderOrEdit(
          chatId,
          `✍ Введите сумму выплаты для ${ShopBot._displayUser(info)} (от 1 до ${curDebt} RUB) ответным сообщением в чат:`,
          {
            replyMarkup: kb([[['⬅ Отмена', `admin:refpay:${refId}`]]]),
            messageId,
          }
        );
        return;
      }

      if (data === 'admin:public_link' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const link = this.publicAccessLink();
        await this.sendMessage(
          chatId,
          `Публичная ссылка доступа:\n${link}\n\nЕё можно публиковать или отправлять многократно.`,
          {
            replyMarkup: kb([
              [{ text: 'Скопировать ссылку', copy_text: link, style: 'primary' }],
              [['Назад в админ-меню', 'admin:menu', 'primary']],
            ]),
          }
        );
        return;
      }

      if (data === 'admin:share_warp' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.sendMessage(chatId, 'Выберите сервер для выдачи Warp / AmneziaWG конфига:', {
          replyMarkup: kb([
            [['🇳🇱 Нидерланды (NL)', 'admin:share_warp_srv:nl']],
            [['🇫🇮 Финляндия (FI)', 'admin:share_warp_srv:fi']],
            [['🇵🇱 Польша (PL)', 'admin:share_warp_srv:pl']],
            [['« Назад в админ-меню', 'admin:menu', 'primary']],
          ]),
        });
        return;
      }

      if (
        (data.startsWith('admin:share_warp_srv:') || data.startsWith('admin:warp_srv:')) &&
        chatId != null &&
        this.isAdmin(user)
      ) {
        await this.answerCallbackQuery(callbackId);
        const srv = data.split(':').pop().toLowerCase();
        await this._mergeSessionState(chatId, 'admin', 'admin_wait_warp_sub_url', {
          admin: true,
          target_server: srv,
          server_code: srv,
        });
        await this.sendMessage(
          chatId,
          `Выбран сервер: ${srv.toUpperCase()}\n\nПришлите ссылку подписки клиента (вида ${this.settings.subscriptionBaseUrl}/<id>) или сам id.`
        );
        return;
      }

      if (data === 'admin:create_invite' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const [code] = await this.store.createInvite({
          maxUses: 1,
          expiresAt: daysFromNow(30),
        });
        await this.sendMessage(
          chatId,
          [
            `Инвайт создан:\n${code}`,
            '',
            'Срок: 30 дн.',
            'Использований: 1',
            '',
            'Покупатель открывает бота по этой ссылке и уже внутри сам выбирает тариф:',
            this.inviteLink(code),
          ].join('\n')
        );
        return;
      }

      if (data === 'admin:create_personal_config' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.sendMessage(chatId, 'Выберите транспорт для вашего админ-конфига:', {
          replyMarkup: kb([
            [['XHTTP', 'admin:personal_transport:xhttp']],
            [['TCP+REALITY', 'admin:personal_transport:tcp']],
          ]),
        });
        return;
      }

      if (data.startsWith('admin:personal_transport:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const transport = data.split(':').pop();
        const res = await this.provisioner.createAdminProfile(transport, user);
        await this.sendMessage(
          chatId,
          `Админ-конфиг создан.\nТранспорт: ${ShopBot.transportLabel(transport)}\nСрок: 36500 дн.\n\n${res.subscription_url}`,
          { protectContent: true }
        );
        return;
      }

      if (data === 'admin:create_test_config' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.sendMessage(chatId, 'Выберите транспорт для 24-часового теста:', {
          replyMarkup: kb([
            [['XHTTP', 'admin:test_transport:xhttp']],
            [['TCP+REALITY', 'admin:test_transport:tcp']],
          ]),
        });
        return;
      }

      if (data.startsWith('admin:test_transport:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const transport = data.split(':').pop();
        const res = await this.provisioner.createTestProfile(transport);
        await this.sendMessage(
          chatId,
          `Тестовый конфиг создан.\nТранспорт: ${ShopBot.transportLabel(transport)}\nСрок: 24 часа\n\n${res.subscription_url}`,
          { protectContent: true }
        );
        return;
      }

      if (data === 'admin:create_hybrid_test_config' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Создаю универсальный тест');
        const res = await this.provisioner.createHybridTestProfile();
        const subUrl = this._hybridSubscriptionUrl(String(res.tcp_sub_id), String(res.xhttp_sub_id));
        const setupUrl = ShopBot._subscriptionSetupUrl(subUrl);
        await this.sendMessage(
          chatId,
          `Универсальный тест TCP+XHTTP создан.\nСрок: 24 часа\n\n${subUrl}`,
          {
            replyMarkup: kb([
              [['Подключить', setupUrl, 'success']],
              [{ text: 'Скопировать ссылку', copy_text: subUrl, style: 'primary' }],
            ]),
            protectContent: true,
          }
        );
        return;
      }

      if (data === 'admin:create_promo' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_promo_type', { admin: true });
        await this.sendMessage(chatId, 'Какой промокод создать?', {
          replyMarkup: kb([
            [['Готовый доступ', 'admin:promo_type:fixed', 'success']],
            [['Скидка на любой тариф', 'admin:promo_type:discount', 'primary']],
          ]),
        });
        return;
      }

      if (data === 'admin:promo_type:fixed' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_promo_transport', {
          admin: true,
          promo_type: 'fixed',
        });
        await this.sendMessage(chatId, 'Выберите транспорт для промокода:', {
          replyMarkup: kb([
            [['Универсальный', 'admin:promo_transport:hybrid', 'primary']],
            [['XHTTP', 'admin:promo_transport:xhttp']],
            [['TCP+REALITY', 'admin:promo_transport:tcp']],
          ]),
        });
        return;
      }

      if (data === 'admin:promo_type:discount' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_promo_discount', {
          admin: true,
          promo_type: 'discount',
        });
        await this.sendMessage(chatId, 'Выберите размер скидки:', {
          replyMarkup: kb([
            [
              ['10%', 'admin:promo_discount:10'],
              ['25%', 'admin:promo_discount:25'],
            ],
            [
              ['50%', 'admin:promo_discount:50'],
              ['75%', 'admin:promo_discount:75'],
            ],
            [['100%', 'admin:promo_discount:100']],
          ]),
        });
        return;
      }

      if (data.startsWith('admin:promo_transport:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const transport = data.split(':').pop();
        await this._mergeSessionState(chatId, 'admin', 'admin_promo_device_limit', {
          admin: true,
          promo_type: 'fixed',
          transport,
        });
        await this.sendMessage(chatId, 'Выберите лимит устройств:', {
          replyMarkup: kb([
            [['3 устройства', 'admin:promo_device_limit:3']],
            [['6 устройств', 'admin:promo_device_limit:6']],
            [['9 устройств', 'admin:promo_device_limit:9']],
            [['Без лимита', 'admin:promo_device_limit:0', 'primary']],
          ]),
        });
        return;
      }

      if (data.startsWith('admin:promo_device_limit:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const deviceLimit = parseInt(data.split(':').pop(), 10);
        await this._mergeSessionState(chatId, 'admin', 'admin_promo_duration', {
          admin: true,
          device_limit: deviceLimit,
        });
        await this.sendMessage(chatId, 'Выберите срок готового доступа:', {
          replyMarkup: kb([
            [
              ['1 месяц', 'admin:promo_months:1'],
              ['3 месяца', 'admin:promo_months:3'],
            ],
            [
              ['6 месяцев', 'admin:promo_months:6'],
              ['12 месяцев', 'admin:promo_months:12'],
            ],
            [['Ввести месяцы вручную', 'admin:promo_months_manual', 'primary']],
            [['Пожизненно', 'admin:promo_duration:36500']],
          ]),
        });
        return;
      }

      if (data === 'admin:promo_months_manual' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_wait_promo_months', { admin: true });
        await this.sendMessage(chatId, 'Отправьте точное количество месяцев целым числом, например 6.');
        return;
      }

      if (data.startsWith('admin:promo_months:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const months = parseInt(data.split(':').pop(), 10);
        const context = await this._mergeSessionState(chatId, 'admin', 'admin_promo_price', {
          admin: true,
          duration_days: months * 30,
          duration_months: months,
        });
        await this._sendAdminPromoPricePrompt(chatId, context);
        return;
      }

      if (data.startsWith('admin:promo_duration:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const durationDays = parseInt(data.split(':').pop(), 10);
        const context = await this._mergeSessionState(
          chatId,
          'admin',
          'admin_promo_price',
          { admin: true, duration_days: durationDays },
          { dropKeys: ['duration_months'] }
        );
        await this._sendAdminPromoPricePrompt(chatId, context);
        return;
      }

      if (data === 'admin:promo_price:manual' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_wait_promo_price', { admin: true });
        await this.sendMessage(chatId, 'Отправьте итоговую цену в рублях целым числом, например 1000.');
        return;
      }

      if (data === 'admin:promo_price:regular' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const context = await this._mergeSessionState(
          chatId,
          'admin',
          'admin_promo_mode',
          { admin: true, discount_percent: 0 },
          { dropKeys: ['fixed_price_rub'] }
        );
        await this._sendAdminPromoModePrompt(chatId, context);
        return;
      }

      if (data === 'admin:promo_price:free' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const context = await this._mergeSessionState(chatId, 'admin', 'admin_promo_mode', {
          admin: true,
          discount_percent: 0,
          fixed_price_rub: 0,
        });
        await this._sendAdminPromoModePrompt(chatId, context);
        return;
      }

      if (data.startsWith('admin:promo_discount:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const discountPercent = parseInt(data.split(':').pop(), 10);
        const session = await this.store.getSession(chatId);
        const context = ShopBot._contextFromSession(session);
        if (context.promo_type === 'discount') {
          const [code] = await this.store.createPromoCode({
            promoType: 'discount',
            transport: 'any',
            durationDays: 0,
            discountPercent,
            deviceLimit: this.settings.defaultDeviceLimit,
            profileMode: 'anonymous',
            maxUses: 1,
          });
          await this.store.setSession(chatId, 'admin', 'menu', { admin: true });
          await this.sendMessage(
            chatId,
            `Промокод создан:\n${code}\n\nТип: скидка на любой тариф\nСкидка: ${discountPercent}%\nИспользований: 1`
          );
          return;
        }
        const updated = await this._mergeSessionState(
          chatId,
          'admin',
          'admin_promo_mode',
          { admin: true, discount_percent: discountPercent },
          { dropKeys: ['fixed_price_rub'] }
        );
        await this._sendAdminPromoModePrompt(chatId, updated);
        return;
      }

      if (data === 'admin:promo_mode:anonymous' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        const session = await this.store.getSession(chatId);
        const context = ShopBot._contextFromSession(session);
        const [code] = await this.store.createPromoCode({
          promoType: 'fixed',
          transport: context.transport,
          durationDays: context.duration_days,
          durationMonths: context.duration_months,
          discountPercent: context.discount_percent || 0,
          fixedPriceRub: context.fixed_price_rub,
          deviceLimit: Number(context.device_limit ?? this.settings.defaultDeviceLimit),
          profileMode: 'anonymous',
          maxUses: 1,
        });
        await this.store.setSession(chatId, 'admin', 'menu', { admin: true });
        await this.sendMessage(
          chatId,
          `Промокод создан:\n${code}\n\nТип: готовый доступ\nТранспорт: ${ShopBot.transportLabel(context.transport)}\nСрок: ${ShopBot.promoDurationLabel(context)}\nРежим: anonymous`
        );
        return;
      }

      if (data === 'admin:promo_mode:family' && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this._mergeSessionState(chatId, 'admin', 'admin_wait_family_label', { admin: true });
        await this.sendMessage(chatId, 'Отправьте подпись профиля, например babuska1');
        return;
      }

      if (data.startsWith('admin:profile:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId);
        await this.showAdminProfile(chatId, data.split(':').slice(2).join(':'));
        return;
      }

      if (data.startsWith('admin:profile_disable:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Отключаю профиль');
        await this.setAdminProfileEnabled(chatId, data.split(':').slice(2).join(':'), false, user);
        return;
      }

      if (data.startsWith('admin:profile_enable:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Включаю профиль');
        await this.setAdminProfileEnabled(chatId, data.split(':').slice(2).join(':'), true, user);
        return;
      }

      if (data.startsWith('admin:profile_warn:') && chatId != null && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Отправляю предупреждение');
        await this.warnAdminProfileOwner(chatId, data.split(':').slice(2).join(':'), user);
        return;
      }

      if (data.startsWith('admin:confirm:') && this.isAdmin(user)) {
        await this.answerCallbackQuery(callbackId, 'Оплата подтверждается');
        const orderPublicId = data.split(':').pop();
        const order = await this.store.getOrder(orderPublicId);
        if (!order) {
          if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} не найден.`);
          return;
        }
        if (order.status === 'cancelled') {
          if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} уже отменён.`);
          return;
        }
        await this.completeOrder(order, `tg:${user.id}`);
        if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} завершён.`);
        return;
      }

      if (data.startsWith('admin:cancel:') && this.isAdmin(user)) {
        const orderPublicId = data.split(':').pop();
        const order = await this.store.getOrder(orderPublicId);
        if (!order) {
          await this.answerCallbackQuery(callbackId);
          if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} не найден.`);
          return;
        }
        if (order.status === 'delivered') {
          await this.answerCallbackQuery(callbackId, 'Заказ уже выдан!', true);
          if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} уже завершён и не может быть отменён.`);
          return;
        }
        if (order.status === 'cancelled') {
          await this.answerCallbackQuery(callbackId);
          if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} уже отменён.`);
          return;
        }
        await this.answerCallbackQuery(callbackId, 'Заказ отменён');
        await this.store.updateOrderStatus(orderPublicId, 'cancelled', {
          actor: `tg:${user.id}`,
        });
        await this.store.recordAdminAction({
          actionType: 'cancel_order',
          targetType: 'order',
          targetPublicId: orderPublicId,
          actor: `tg:${user.id}`,
        });
        if (order.customer_chat_id) {
          await this._mergeSessionState(order.customer_chat_id, 'public', 'menu', null, {
            dropKeys: [ACTION_GUARD_KEY, 'order_public_id', 'pending_promo', 'pending_promo_id'],
          });
          await this.sendMessage(order.customer_chat_id, 'Заказ отменён. Если нужно, создайте новый.');
        }
        if (chatId != null) await this.sendMessage(chatId, `Заказ ${orderPublicId} отменён.`);
        return;
      }

      await this.answerCallbackQuery(callbackId, 'Неизвестное действие', true);
    } catch (err) {
      console.error('Callback handling failed:', err);
      await this.answerCallbackQuery(callbackId, 'Ошибка выполнения', true);
      if (chatId != null) {
        await this.sendMessage(
          chatId,
          'Действие временно не завершилось. Повторный клик не создаст дубликат. Попробуйте ещё раз через 10-20 сек.'
        );
      }
    }
  }
}
