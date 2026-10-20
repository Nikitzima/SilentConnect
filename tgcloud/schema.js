import {
  table,
  integer,
  text,
  json,
  index,
  uniqueIndex,
  sql,
} from 'sdk/db';

export const chatSessions = table('chat_sessions', {
  chatId: text('chat_id').primaryKey(),
  scope: text('scope').notNull(),
  state: text('state').notNull(),
  contextJson: json('context_json').notNull().default({}),
  updatedAt: integer('updated_at').notNull(),
});

export const inviteTokens = table('invite_tokens', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  codeHash: text('code_hash').notNull().unique(),
  codePreview: text('code_preview').notNull(),
  purpose: text('purpose').notNull().default('storefront'),
  maxUses: integer('max_uses').notNull().default(1),
  usedCount: integer('used_count').notNull().default(0),
  expiresAt: integer('expires_at'),
  enabled: integer('enabled').notNull().default(1),
  createdAt: integer('created_at').notNull(),
  note: text('note'),
});

export const promoCodes = table('promo_codes', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  codeHash: text('code_hash').notNull().unique(),
  codePreview: text('code_preview').notNull(),
  promoType: text('promo_type').notNull().default('fixed'),
  transport: text('transport').notNull(),
  durationDays: integer('duration_days').notNull(),
  durationMonths: integer('duration_months'),
  discountPercent: integer('discount_percent').notNull(),
  fixedPriceRub: integer('fixed_price_rub'),
  deviceLimit: integer('device_limit').notNull().default(3),
  profileMode: text('profile_mode').notNull(),
  familyLabel: text('family_label'),
  maxUses: integer('max_uses').notNull().default(1),
  usedCount: integer('used_count').notNull().default(0),
  expiresAt: integer('expires_at'),
  enabled: integer('enabled').notNull().default(1),
  createdAt: integer('created_at').notNull(),
  lastUsedAt: integer('last_used_at'),
});

export const orders = table(
  'orders',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    publicId: text('public_id').notNull().unique(),
    kind: text('kind').notNull(),
    status: text('status').notNull(),
    transport: text('transport').notNull(),
    durationDays: integer('duration_days').notNull(),
    profileMode: text('profile_mode').notNull(),
    familyLabel: text('family_label'),
    basePriceRub: integer('base_price_rub').notNull(),
    finalPriceRub: integer('final_price_rub').notNull(),
    promoId: integer('promo_id'),
    inviteId: integer('invite_id'),
    customerChatId: text('customer_chat_id'),
    customerEmail: text('customer_email').notNull().default(''),
    managerChatId: text('manager_chat_id'),
    managerMessageId: integer('manager_message_id'),
    privacyAck: integer('privacy_ack').notNull().default(0),
    lossPolicyAck: integer('loss_policy_ack').notNull().default(0),
    termsVersion: text('terms_version').notNull(),
    provisionedProfileId: integer('provisioned_profile_id'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
    closedAt: integer('closed_at'),
    metaJson: json('meta_json').notNull().default({}),
    externalId: text('external_id'),
    webTokenHash: text('web_token_hash'),
    version: integer('version').notNull().default(0),
  },
  (t) => ({
    customerStatusIdx: index('ix_orders_customer_status').on(t.customerChatId, t.status),
    statusCreatedIdx: index('ix_orders_status_created').on(t.status, t.createdAt),
    customerEmailIdx: index('ix_orders_customer_email').on(t.customerEmail),
    externalIdUq: uniqueIndex('uq_orders_external_id')
      .on(t.externalId)
      .where(sql`${t.externalId} IS NOT NULL`),
  })
);

export const profiles = table(
  'profiles',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    publicId: text('public_id').notNull().unique(),
    xuiInboundId: integer('xui_inbound_id').notNull(),
    transport: text('transport').notNull(),
    profileMode: text('profile_mode').notNull(),
    familyLabel: text('family_label'),
    xuiEmail: text('xui_email').notNull().unique(),
    xuiClientId: text('xui_client_id').notNull(),
    status: text('status').notNull(),
    createdAt: integer('created_at').notNull(),
    expiresAt: integer('expires_at').notNull(),
    lastRenewedAt: integer('last_renewed_at'),
    deletedAt: integer('deleted_at'),
    notes: text('notes'),
    awgQuotaBytes: integer('awg_quota_bytes').notNull().default(0),
    awgUsedBytes: integer('awg_used_bytes').notNull().default(0),
    awgResetAt: integer('awg_reset_at'),
    deviceLimit: integer('device_limit').notNull().default(3),
  },
  (t) => ({
    statusExpiresIdx: index('ix_profiles_status_expires').on(t.status, t.expiresAt),
  })
);

export const profileOwners = table(
  'profile_owners',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    profilePublicId: text('profile_public_id').notNull().unique(),
    userId: text('user_id').notNull(),
    chatId: text('chat_id').notNull(),
    sourceOrderPublicId: text('source_order_public_id'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => ({
    userIdIdx: index('idx_profile_owners_user_id').on(t.userId, t.updatedAt),
  })
);

export const profileReminders = table(
  'profile_reminders',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    profilePublicId: text('profile_public_id').notNull(),
    reminderKind: text('reminder_kind').notNull(),
    sentAt: integer('sent_at').notNull(),
  },
  (t) => ({
    profileKindUq: uniqueIndex('uq_profile_reminders_kind').on(t.profilePublicId, t.reminderKind),
  })
);

export const adminActions = table(
  'admin_actions',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    actionType: text('action_type').notNull(),
    targetType: text('target_type').notNull(),
    targetPublicId: text('target_public_id').notNull(),
    actor: text('actor').notNull(),
    createdAt: integer('created_at').notNull(),
    metaJson: json('meta_json').notNull().default({}),
  },
  (t) => ({
    lookupIdx: index('ix_admin_actions_lookup').on(t.actionType, t.targetType, t.targetPublicId),
  })
);

export const telegramUsers = table('telegram_users', {
  userId: text('user_id').primaryKey(),
  chatId: text('chat_id').notNull(),
  username: text('username'),
  firstName: text('first_name'),
  lastName: text('last_name'),
  isBot: integer('is_bot').notNull().default(0),
  firstSeenAt: integer('first_seen_at').notNull(),
  lastSeenAt: integer('last_seen_at').notNull(),
});

export const trialRedemptions = table('trial_redemptions', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: text('user_id').notNull().unique(),
  chatId: text('chat_id').notNull(),
  status: text('status').notNull(),
  transport: text('transport').notNull().default('tcp'),
  orderPublicId: text('order_public_id'),
  profilePublicId: text('profile_public_id'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
  deliveredAt: integer('delivered_at'),
  metaJson: json('meta_json').notNull().default({}),
});

export const referrers = table('referrers', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: text('user_id').notNull().unique(),
  chatId: text('chat_id').notNull(),
  code: text('code').notNull().unique(),
  commissionPercent: integer('commission_percent').notNull().default(10),
  status: text('status').notNull().default('active'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

export const referralAttributions = table(
  'referral_attributions',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    referrerId: integer('referrer_id').notNull(),
    referredUserId: text('referred_user_id').notNull().unique(),
    referredChatId: text('referred_chat_id').notNull(),
    sourceCode: text('source_code').notNull(),
    createdAt: integer('created_at').notNull(),
    firstOrderPublicId: text('first_order_public_id'),
  },
  (t) => ({
    referrerIdx: index('ix_referral_attr_referrer').on(t.referrerId),
  })
);

export const referralLedger = table(
  'referral_ledger',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    referrerId: integer('referrer_id').notNull(),
    referredUserId: text('referred_user_id').notNull(),
    orderPublicId: text('order_public_id').notNull().unique(),
    baseAmountRub: integer('base_amount_rub').notNull(),
    amountRub: integer('amount_rub').notNull(),
    commissionPercent: integer('commission_percent').notNull(),
    status: text('status').notNull().default('pending'),
    createdAt: integer('created_at').notNull(),
    paidAt: integer('paid_at'),
    payoutId: integer('payout_id'),
    metaJson: json('meta_json').notNull().default({}),
  },
  (t) => ({
    referrerIdx: index('ix_referral_ledger_referrer').on(t.referrerId),
  })
);

export const referralPayouts = table(
  'referral_payouts',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    referrerId: integer('referrer_id').notNull(),
    amountRub: integer('amount_rub').notNull(),
    actor: text('actor').notNull(),
    createdAt: integer('created_at').notNull(),
    metaJson: json('meta_json').notNull().default({}),
  },
  (t) => ({
    referrerIdx: index('ix_referral_payouts_referrer').on(t.referrerId),
  })
);

export const webhookEvents = table(
  'webhook_events',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    gateway: text('gateway').notNull(),
    eventId: text('event_id').notNull(),
    eventType: text('event_type').notNull(),
    orderPublicId: text('order_public_id'),
    processedAt: integer('processed_at').notNull(),
    status: text('status').notNull().default('processed'),
    payloadSha256: text('payload_sha256'),
    attempts: integer('attempts').notNull().default(1),
    lastError: text('last_error'),
    updatedAt: integer('updated_at'),
  },
  (t) => ({
    gatewayEventUq: uniqueIndex('uq_webhook_gateway_event').on(t.gateway, t.eventId),
  })
);

export const orderStateLog = table(
  'order_state_log',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    orderPublicId: text('order_public_id').notNull(),
    fromStatus: text('from_status'),
    toStatus: text('to_status').notNull(),
    actor: text('actor').notNull(),
    reason: text('reason'),
    createdAt: integer('created_at').notNull(),
  },
  (t) => ({
    orderIdx: index('ix_order_state_log_order').on(t.orderPublicId, t.id),
  })
);

export const paymentConfirmations = table('payment_confirmations', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  orderPublicId: text('order_public_id').notNull().unique(),
  idempotencyKey: text('idempotency_key').notNull().unique(),
  confirmedBy: text('confirmed_by').notNull(),
  confirmedById: text('confirmed_by_id'),
  amountRub: integer('amount_rub').notNull(),
  expectedAmountRub: integer('expected_amount_rub').notNull(),
  method: text('method').notNull().default('manual_sbp'),
  reference: text('reference'),
  status: text('status').notNull(),
  createdAt: integer('created_at').notNull(),
  finalizedAt: integer('finalized_at'),
  error: text('error'),
  metaJson: json('meta_json').notNull().default({}),
});

export const magicLinks = table('magic_links', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  tokenHash: text('token_hash').notNull().unique(),
  email: text('email').notNull(),
  createdAt: integer('created_at').notNull(),
  expiresAt: integer('expires_at').notNull(),
  usedAt: integer('used_at'),
  requestIp: text('request_ip'),
});

export const awgSlots = table(
  'awg_slots',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    profilePublicId: text('profile_public_id').notNull(),
    slotIndex: integer('slot_index').notNull(),
    slotLabel: text('slot_label').notNull(),
    publicKey: text('public_key').notNull().unique(),
    privateKeyEnc: text('private_key_enc').notNull(),
    presharedKey: text('preshared_key'),
    clientIp: text('client_ip').notNull(),
    enabled: integer('enabled').notNull().default(1),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
    serverCode: text('server_code').notNull().default('nl'),
  },
  (t) => ({
    profileIdx: index('ix_awg_slots_profile').on(t.profilePublicId),
    publicKeyIdx: index('ix_awg_slots_public_key').on(t.publicKey),
    clientIpIdx: index('ix_awg_slots_client_ip').on(t.clientIp),
    profileSlotServerUq: uniqueIndex('uq_awg_slots_profile_slot_srv').on(
      t.profilePublicId,
      t.slotIndex,
      t.serverCode
    ),
    serverIpUq: uniqueIndex('uq_awg_slots_server_ip').on(t.serverCode, t.clientIp),
  })
);

export const awgTrafficLedger = table(
  'awg_traffic_ledger',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    nodeId: text('node_id').notNull(),
    slotId: integer('slot_id'),
    profilePublicId: text('profile_public_id').notNull(),
    deltaRxBytes: integer('delta_rx_bytes').notNull().default(0),
    deltaTxBytes: integer('delta_tx_bytes').notNull().default(0),
    collectedAt: integer('collected_at').notNull(),
  },
  (t) => ({
    profileIdx: index('ix_awg_traffic_ledger_profile').on(t.profilePublicId, t.collectedAt),
    slotIdx: index('ix_awg_traffic_ledger_slot').on(t.slotId),
    nodeIdx: index('ix_awg_traffic_ledger_node').on(t.nodeId, t.collectedAt),
  })
);
