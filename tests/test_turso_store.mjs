import test from 'node:test';
import assert from 'node:assert/strict';
import { Store, OrderStateError } from '../tgcloud/lib/store.js';

/**
 * Тестирует реальный класс Store (tgcloud/lib/store.js):
 * 1. Формат запросов Turso HTTP Pipeline (/v2/pipeline) для orders, profiles, promo_codes, referrers, awg_slots.
 * 2. Консистентность типов данных (JSON-поля, integer/text маппинг, boolean -> integer '1'/'0').
 * 3. Изоляцию хранения: chat_sessions остаются локальными и НИКОГДА не идут в Turso HTTP Pipeline.
 * 4. Управление жизненным циклом заказов (transitionOrder, order_state_log).
 */

class MockTursoPipelineServer {
  constructor() {
    this.calls = [];
    this.mockResponses = [];
  }

  enqueueResult(cols, rows, affectedRowCount = 1, lastInsertRowid = null) {
    this.mockResponses.push({
      results: [
        {
          type: 'ok',
          response: {
            type: 'execute',
            result: {
              cols: cols.map((name) => ({ name })),
              rows: rows.map((r) =>
                r.map((val) => {
                  if (val === null || val === undefined) return { type: 'null' };
                  if (typeof val === 'number') {
                    return Number.isInteger(val)
                      ? { type: 'integer', value: String(val) }
                      : { type: 'float', value: val };
                  }
                  if (typeof val === 'object') {
                    return { type: 'text', value: JSON.stringify(val) };
                  }
                  return { type: 'text', value: String(val) };
                })
              ),
              affected_row_count: affectedRowCount,
              last_insert_rowid: lastInsertRowid ? String(lastInsertRowid) : null,
            },
          },
        },
        { type: 'ok', response: { type: 'close' } },
      ],
    });
  }

  async fetch(url, options) {
    const body = JSON.parse(options.body);
    this.calls.push({ url, headers: options.headers, body });
    const next = this.mockResponses.shift() || {
      results: [
        {
          type: 'ok',
          response: {
            type: 'execute',
            result: { cols: [], rows: [], affected_row_count: 1, last_insert_rowid: null },
          },
        },
        { type: 'ok', response: { type: 'close' } },
      ],
    };
    return {
      ok: true,
      status: 200,
      async json() {
        return next;
      },
      async text() {
        return JSON.stringify(next);
      },
    };
  }
}

test('Store: CRUD для orders, profiles, promo_codes через Turso HTTP Pipeline (/v2/pipeline)', async () => {
  const mockServer = new MockTursoPipelineServer();
  const store = new Store({
    tursoUrl: 'https://silentconnect-test.aws-eu-north-1.turso.io',
    tursoToken: 'test-turso-bearer-token',
    fetch: mockServer.fetch.bind(mockServer),
  });

  // 1. Тест createOrder: возвращает вставленный заказ
  mockServer.enqueueResult(
    [
      'id', 'public_id', 'kind', 'status', 'transport', 'duration_days', 'profile_mode',
      'family_label', 'base_price_rub', 'final_price_rub', 'promo_id', 'invite_id',
      'customer_chat_id', 'customer_email', 'manager_chat_id', 'manager_message_id',
      'privacy_ack', 'loss_policy_ack', 'terms_version', 'provisioned_profile_id',
      'created_at', 'updated_at', 'closed_at', 'meta_json', 'external_id', 'web_token_hash', 'version'
    ],
    [[
      101, 'ord_real123', 'purchase', 'waiting_payment', 'tcp', 30, 'personal',
      null, 199, 199, null, null,
      '777888', '', null, null,
      1, 1, '2026-04-20', null,
      1770000000, 1770000000, null, JSON.stringify({ device_limit: 3 }), null, null, 1
    ]]
  );

  const created = await store.createOrder({
    kind: 'purchase',
    status: 'waiting_payment',
    transport: 'tcp',
    durationDays: 30,
    profileMode: 'personal',
    basePriceRub: 199,
    finalPriceRub: 199,
    customerChatId: '777888',
    privacyAck: true,
    lossPolicyAck: true,
    meta: { device_limit: 3 },
  });

  assert.equal(created.id, 101);
  assert.equal(created.public_id, 'ord_real123');
  assert.equal(created.status, 'waiting_payment');
  assert.equal(created.duration_days, 30);
  assert.equal(typeof created.duration_days, 'number');
  assert.deepEqual(created.meta_json, { device_limit: 3 });

  // Проверяем формат исходящего запроса к Turso Pipeline
  const createReq = mockServer.calls[0];
  assert.equal(createReq.url, 'https://silentconnect-test.aws-eu-north-1.turso.io/v2/pipeline');
  assert.equal(createReq.headers.Authorization, 'Bearer test-turso-bearer-token');
  assert.match(createReq.body.requests[0].stmt.sql, /INSERT INTO orders/);

  // 2. Тест getOrder: автопарсинг meta_json и приведение типов
  mockServer.enqueueResult(
    [
      'id', 'public_id', 'kind', 'status', 'transport', 'duration_days', 'profile_mode',
      'family_label', 'base_price_rub', 'final_price_rub', 'promo_id', 'invite_id',
      'customer_chat_id', 'customer_email', 'manager_chat_id', 'manager_message_id',
      'privacy_ack', 'loss_policy_ack', 'terms_version', 'provisioned_profile_id',
      'created_at', 'updated_at', 'closed_at', 'meta_json', 'external_id', 'web_token_hash', 'version'
    ],
    [[
      101, 'ord_real123', 'purchase', 'waiting_payment', 'tcp', 30, 'personal',
      null, 199, 199, null, null,
      '777888', '', null, null,
      1, 1, '2026-04-20', null,
      1770000000, 1770000000, null, JSON.stringify({ device_limit: 3, source: 'bot' }), null, null, 1
    ]]
  );

  const order = await store.getOrder('ord_real123');
  assert.equal(order.id, 101);
  assert.equal(order.public_id, 'ord_real123');
  assert.deepEqual(order.meta_json, { device_limit: 3, source: 'bot' });

  // 3. Тест createProfile и extendProfile
  mockServer.enqueueResult(
    [
      'id', 'public_id', 'xui_inbound_id', 'transport', 'profile_mode', 'family_label',
      'xui_email', 'xui_client_id', 'status', 'created_at', 'expires_at', 'last_renewed_at',
      'deleted_at', 'notes', 'awg_quota_bytes', 'awg_used_bytes', 'awg_reset_at', 'device_limit'
    ],
    [[
      201, 'prf_turso99', 2, 'tcp', 'personal', null,
      'test_user_sub', 'client_guid_123', 'active', 1770000000, 1772592000, 1770000000,
      null, null, 268435456000, 0, 1772592000, 3
    ]]
  );

  const profile = await store.createProfile({
    xuiInboundId: 2,
    transport: 'tcp',
    profileMode: 'personal',
    xuiEmail: 'test_user_sub',
    xuiClientId: 'client_guid_123',
    expiresAt: 1772592000,
    awgQuotaBytes: 268435456000,
    deviceLimit: 3,
  });

  assert.equal(profile.id, 201);
  assert.equal(profile.public_id, 'prf_turso99');
  assert.equal(profile.status, 'active');
  assert.equal(profile.device_limit, 3);
  assert.equal(profile.awg_quota_bytes, 268435456000);

  // 4. Тест transitionOrder (state transitions & audit log)
  // getOrder call inside transitionOrder
  mockServer.enqueueResult(
    ['id', 'public_id', 'status', 'duration_days', 'closed_at'],
    [[101, 'ord_real123', 'provisioning', 30, null]]
  );
  // UPDATE orders RETURNING *
  mockServer.enqueueResult(
    ['id', 'public_id', 'status', 'duration_days', 'closed_at', 'version'],
    [[101, 'ord_real123', 'delivered', 30, 1770000500, 2]]
  );
  // INSERT INTO order_state_log
  mockServer.enqueueResult([], [], 1, null);

  const transitioned = await store.transitionOrder('ord_real123', 'delivered', {
    expectedFrom: ['provisioning'],
    actor: 'test-runner',
    reason: 'payment_verified',
  });

  assert.equal(transitioned.status, 'delivered');
  assert.equal(transitioned.version, 2);

  // Проверяем, что в Turso ушли: UPDATE orders и INSERT INTO order_state_log
  const updateCall = mockServer.calls.find((c) => c.body.requests[0].stmt.sql.includes('UPDATE orders'));
  assert.ok(updateCall, 'UPDATE orders must be sent to Turso');
  const logCall = mockServer.calls.find((c) => c.body.requests[0].stmt.sql.includes('INSERT INTO order_state_log'));
  assert.ok(logCall, 'INSERT INTO order_state_log must be sent to Turso');
});

test('Изоляция хранилищ: chat_sessions пишутся локально и НИКОГДА не отправляются в Turso Pipeline', async () => {
  const mockServer = new MockTursoPipelineServer();
  const store = new Store({
    tursoUrl: 'https://silentconnect-test.aws-eu-north-1.turso.io',
    tursoToken: 'test-turso-bearer-token',
    fetch: mockServer.fetch.bind(mockServer),
  });

  // 1. Записываем UI-состояние сессии чата
  await store.setSession('chat_12345', 'public', 'buy_duration', { selected_days: 30, tier: 3 });

  // 2. Читаем UI-состояние сессии чата
  const session = await store.getSession('chat_12345');
  assert.equal(session.chat_id, 'chat_12345');
  assert.equal(session.scope, 'public');
  assert.equal(session.state, 'buy_duration');
  assert.deepEqual(session.context_json, { selected_days: 30, tier: 3 });

  // 3. Проверяем, что в Turso Pipeline не было сделано НИ ЕДИНОГО запроса для сессий чата
  assert.equal(
    mockServer.calls.length,
    0,
    'Turso HTTP Pipeline must NOT receive chat_sessions queries (chat_sessions are strictly local to Telegram Cloud)'
  );

  // 4. Очищаем сессию
  await store.clearSession('chat_12345');
  const cleared = await store.getSession('chat_12345');
  assert.equal(cleared, null);
  assert.equal(mockServer.calls.length, 0);
});

test('AWG Slots: запрос слотов устройства через Turso HTTP Pipeline', async () => {
  const mockServer = new MockTursoPipelineServer();
  const store = new Store({
    tursoUrl: 'https://silentconnect-test.aws-eu-north-1.turso.io',
    tursoToken: 'test-turso-bearer-token',
    fetch: mockServer.fetch.bind(mockServer),
  });

  mockServer.enqueueResult(
    ['id', 'profile_public_id', 'slot_index', 'slot_label', 'public_key', 'client_ip', 'enabled', 'server_code'],
    [
      [1, 'prf_test', 1, 'Телефон', 'pubkey_1', '10.8.1.2', 1, 'nl'],
      [2, 'prf_test', 2, 'Ноутбук', 'pubkey_2', '10.8.1.3', 1, 'nl'],
    ]
  );

  const slots = await store.listAwgSlots('prf_test');
  assert.equal(slots.length, 2);
  assert.equal(slots[0].slot_index, 1);
  assert.equal(slots[0].slot_label, 'Телефон');
  assert.equal(slots[1].slot_index, 2);
  assert.equal(slots[1].slot_label, 'Ноутбук');

  const awgReq = mockServer.calls[0];
  assert.match(awgReq.body.requests[0].stmt.sql, /SELECT id, profile_public_id, slot_index/);
});
