export const REFERRAL_INVITEE_DISCOUNT_PERCENT = 10;
export const REFERRAL_COMMISSION_PERCENT = 10;
export const REFERRAL_PAYOUT_MIN_RUB = 500;
export const REFERRAL_MONTHLY_REPORT_DAY = 28;

export const TEST_PROFILE_CLEANUP_INTERVAL = 60;
export const ACTION_GUARD_KEY = '_action_guard';
export const ACTION_GUARD_TTL_SECONDS = 120;
export const WAITING_PAYMENT_EXPIRY_SECONDS = 6 * 3600;
export const ORDER_NOTIFICATION_BUMP_SECONDS = 30 * 60;
export const PAYMENT_REPORT_REPEAT_SECONDS = 10 * 60;
export const TRIAL_TRANSPORT = 'tcp';
export const PUBLIC_ACCESS_START_CODE = 'open';

export const PUBLIC_MENU_DROP_KEYS = [
  'pending_promo',
  'pending_promo_id',
  'promo_return',
  'renewal_profile_public_id',
];

export const TEST_PROFILE_NOTES = 'admin_test_24h_auto_delete';
export const ADMIN_PROFILE_NOTES = 'admin_personal_long_lived';
export const PUBLIC_TRIAL_PROFILE_NOTES = 'public_trial_7d_auto_delete';

export const AWG_TIER_QUOTAS_GB = {
  3: 250,
  6: 500,
  9: 1000,
};

export const AWG_TIER_QUOTAS_BYTES = {
  3: 250 * 1024 * 1024 * 1024,
  6: 500 * 1024 * 1024 * 1024,
  9: 1000 * 1024 * 1024 * 1024,
};

export const SETTINGS = {
  brandName: 'SilentConnect',
  telegramBotUsername: 'SilentConnectVPNBot',
  supportTgUrl: 'https://t.me/SilentConnectHelp',
  supportEmail: 'support@example.com',

  // Telegram User ID администраторов (числа)
  adminUserIds: (process.env?.ADMIN_TG_IDS || '')
    .split(',')
    .map((s) => Number(s.trim()))
    .filter(Boolean),
  adminUsernames: (process.env?.ADMIN_TG_USERNAMES || '')
    .split(',')
    .map((s) => s.trim().replace(/^@/, ''))
    .filter(Boolean),

  // URL сервисов SilentConnect
  subscriptionBaseUrl: process.env?.SUBSCRIPTION_BASE_URL || 'https://sub.example.com/sub/json',
  webPublicBaseUrl: process.env?.WEB_PUBLIC_BASE_URL || 'https://shop.example.com',

  // URL и секрет моста к нодам кластера (NL Master -> PL Standby)
  bridgeUrl: process.env?.BRIDGE_URL || 'https://nl.example.com/api/bridge',
  bridgeUrlStandby: process.env?.BRIDGE_URL_STANDBY || 'https://pl.example.com/api/bridge',
  bridgeNodes: [
    { code: 'nl', url: process.env?.BRIDGE_URL || 'https://nl.example.com/api/bridge', timeoutMs: 3000 },
    { code: 'pl', url: process.env?.BRIDGE_URL_STANDBY || 'https://pl.example.com/api/bridge', timeoutMs: 3000 },
  ],
  clusterSyncSecret: process.env?.SERVERLESS_BRIDGE_SECRET || process.env?.CLUSTER_SYNC_SECRET || '',
  serverPepper: process.env?.SERVER_PEPPER || 'silentconnect-pepper-secret-v1',

  // Единый источник правды (Turso Database Cloud)
  tursoUrl: process.env?.TURSO_DATABASE_URL || '',
  tursoToken: process.env?.TURSO_AUTH_TOKEN || '',

  // Настройки X-UI
  xuiXhttpInboundId: Number(process.env?.XUI_XHTTP_INBOUND_ID || 1),
  xuiTcpInboundId: Number(process.env?.XUI_TCP_INBOUND_ID || 2),

  // Тарифная сетка (базовые месячные цены в рублях)
  monthlyPriceXhttpRub: 149,
  monthlyPriceTcpRub: 149,
  monthlyPrice3DevicesRub: 149,
  monthlyPrice6DevicesRub: 199,
  monthlyPrice9DevicesRub: 235,
  defaultDeviceLimit: 3,

  // Режим витрины
  inviteRequired: false,
  termsVersion: '2026-04-20',
  purgeAfterDays: 90,

  // Реквизиты ручной оплаты (fallback)
  paymentInstructionsText:
    'Оплата пока подтверждается вручную. После перевода дождитесь подтверждения менеджером.',
  paymentTransferUrl: process.env?.PAYMENT_TRANSFER_URL || '',
  paymentBankNote:
    'Приоритетно переводить в МТС Банк. Если удобнее, можно Ozon Банк или Т-Банк.',

  // Platega.io
  plategaEnabled: process.env?.PLATEGA_ENABLED === 'true' || true,
  plategaBaseUrl: process.env?.PLATEGA_BASE_URL || 'https://app.platega.io',
  plategaMerchantIdBot: process.env?.PLATEGA_MERCHANT_ID_BOT || '00000000-0000-0000-0000-000000000001',
  plategaMerchantIdWeb: process.env?.PLATEGA_MERCHANT_ID_WEB || '00000000-0000-0000-0000-000000000002',
  plategaSecret: process.env?.PLATEGA_SECRET || '',
  plategaSecretBot: process.env?.PLATEGA_SECRET_BOT || process.env?.PLATEGA_SECRET || '',
  plategaSecretWeb: process.env?.PLATEGA_SECRET_WEB || process.env?.PLATEGA_SECRET || '',

  // Digiseller
  digisellerEnabled: process.env?.DIGISELLER_ENABLED === 'true' || false,
  digisellerSellerId: process.env?.DIGISELLER_SELLER_ID || '1348126',
  digisellerApiKey: process.env?.DIGISELLER_API_KEY || '',
  digisellerSecretKey: process.env?.DIGISELLER_SECRET_KEY || '',
  digisellerProductId: process.env?.DIGISELLER_PRODUCT_ID || '',
  digisellerMinPriceRub: Number(process.env?.DIGISELLER_MIN_PRICE_RUB || 149),
};
