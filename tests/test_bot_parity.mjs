import test from 'node:test';
import assert from 'node:assert/strict';
import { Provisioner } from '../tgcloud/lib/provisioner.js';
import { ShopBot } from '../tgcloud/lib/bot.js';

test('Provisioner.renewProfile passes profile_public_id and fails closed on bridge error', async () => {
  let bridgeCalledWith = null;
  const mockProvisioner = new Provisioner({
    settings: {
      bridgeSecret: 'sec',
      nlBridgeUrl: 'https://nl.example.com/api/bridge',
      subscriptionBaseUrl: 'https://sub.example.com/json',
      defaultDeviceLimit: 3,
    },
    store: {
      async getProfile(id) {
        return {
          public_id: id,
          xui_email: 'ord_123',
          xui_inbound_id: 2,
          expires_at: 1780000000,
          status: 'active',
        };
      },
      async extendProfile(id, exp) {
        return { public_id: id, expires_at: exp };
      },
    },
    fetch: async (url, opts) => {
      const body = JSON.parse(opts.body);
      bridgeCalledWith = body;
      return {
        ok: true,
        json: async () => ({
          ok: true,
          result: { sub_id: 'sub_new', expires_at: 1782592000 },
        }),
      };
    },
  });

  const res = await mockProvisioner.renewProfile('prof_abc', 30, { deviceLimit: 6 });
  assert.equal(res.sub_id, 'sub_new');
  assert.equal(bridgeCalledWith.action, 'renew_profile');
  assert.equal(bridgeCalledWith.profile_public_id, 'prof_abc');
  assert.equal(bridgeCalledWith.device_limit, 6);

  // Failure scenario
  const failingProvisioner = new Provisioner({
    settings: {
      bridgeSecret: 'sec',
      nlBridgeUrl: 'https://nl.example.com/api/bridge',
      defaultDeviceLimit: 3,
    },
    store: {
      async getProfile(id) {
        return { public_id: id, xui_email: 'ord_123', expires_at: 1780000000, status: 'active' };
      },
    },
    fetch: async () => ({
      ok: true,
      json: async () => ({ ok: false, errors: ['node_unavailable'] }),
    }),
  });

  await assert.rejects(
    async () => failingProvisioner.renewProfile('prof_abc', 30),
    /Failed to renew profile/
  );
});

test('ShopBot admin:cancel does NOT cancel delivered orders', async () => {
  const messagesSent = [];
  const callbacksAnswered = [];
  let orderUpdatedTo = null;

  const bot = new ShopBot({
    adminUserIds: [123],
    adminUsernames: ['admin'],
  });

  bot.isAdmin = () => true;
  bot.answerCallbackQuery = async (id, text, alert) => {
    callbacksAnswered.push({ id, text, alert });
  };
  bot.sendMessage = async (chatId, text) => {
    messagesSent.push({ chatId, text });
  };

  bot.store = {
    async getOrder(id) {
      return { public_id: id, status: 'delivered', customer_chat_id: 999 };
    },
    async updateOrderStatus(id, status) {
      orderUpdatedTo = status;
    },
  };

  await bot.handleCallback({
    id: 'cb_1',
    from: { id: 123, username: 'admin' },
    message: { chat: { id: 123 }, message_id: 42 },
    data: 'admin:cancel:ord_already_delivered',
  });

  assert.equal(orderUpdatedTo, null, 'Status must NOT transition to cancelled if already delivered');
  assert.ok(callbacksAnswered.some((c) => c.text?.includes('уже выдан')));
  assert.ok(messagesSent.some((m) => m.text?.includes('уже завершён')));
});

test('ShopBot createStandardOrder consumes invite code', async () => {
  let inviteConsumed = null;
  const bot = new ShopBot({ inviteRequired: true });
  bot.sendMessage = async () => {};
  bot.notifyAdminsAboutOrder = async () => {};
  bot._waitingPaymentMessage = async () => 'pay now';
  bot._publicWaitingPaymentMarkup = async () => ({ inline_keyboard: [] });
  bot._publicHasPurchaseAccess = async () => true;
  bot._claimAction = async () => [true, null];
  bot._freshActiveOrderForChat = async () => null;
  bot._completeAction = async () => {};

  bot.store = {
    async getSession() {
      return {
        scope: 'public',
        state: 'buy_confirm',
        context_json: { invite_id: 777, buy_device_limit: 3, buy_duration_days: 30 },
      };
    },
    async setSession() {},
    async getReferralAttributionForUser() { return null; },
    async countDeliveredPaidOrders() { return 0; },
    async createOrder(o) { return { ...o, public_id: 'ord_test_inv' }; },
    async consumeInvite(id) {
      inviteConsumed = id;
      return true;
    },
  };

  await bot.createStandardOrder(555, {
    code: 'tcp_30d_3dev',
    transport: 'tcp',
    durationDays: 30,
    priceRub: 149,
    deviceLimit: 3,
    profileMode: 'anonymous',
  });

  assert.equal(inviteConsumed, 777, 'Invite ID 777 must be consumed upon order creation');
});
