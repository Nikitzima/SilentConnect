import test from 'node:test';
import assert from 'node:assert/strict';

/**
 * Тестирует двухнодовый провижининг (NL Master -> PL Standby -> pending_provision):
 * 1. NL онлайн -> успешный провижининг, возвращается реальный sub_id от X-UI.
 * 2. NL лежит (таймаут 3с / HTTP 502) -> мгновенный автоматический запрос на PL -> возвращается реальный sub_id от PL.
 * 3. Обе ноды лежат -> заказ переводится в status='pending_provision', админам уходит алерт,
 *    клиенту возвращается статус очереди, и НИКОГДА не генерируется фейковый randomSubscriptionId().
 */

import { provisionWithFailover, DEFAULT_NODES as NODES } from '../tgcloud/lib/provisioner.js';

test('Сценарий 1: NL Master онлайн -> провижининг выполняется на NL с реальным sub_id', async () => {
  const calledUrls = [];
  let finalStatus = null;

  const res = await provisionWithFailover({
    order: { public_id: 'ord_nl_ok', transport: 'tcp', duration_days: 30 },
    fetchFn: async (url) => {
      calledUrls.push(url);
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            ok: true,
            sub_id: 'real_xui_sub_nl_998877',
            subscription_url: 'https://sub.example.com/json/real_xui_sub_nl_998877',
          };
        },
      };
    },
    updateOrderStatusFn: async (_id, st) => {
      finalStatus = st;
    },
    notifyAdminsFn: async () => {
      assert.fail('Admins should not be alerted when NL succeeds');
    },
  });

  assert.equal(calledUrls.length, 1, 'PL should not be called if NL succeeded');
  assert.match(calledUrls[0], /192\.0\.2\.1/);
  assert.equal(res.status, 'delivered');
  assert.equal(res.node, 'nl');
  assert.equal(res.sub_id, 'real_xui_sub_nl_998877');
  assert.equal(finalStatus, 'delivered');
});

test('Сценарий 2: NL таймаут (3с) -> автоматический failover на PL Standby -> успех', async () => {
  const calledUrls = [];
  let finalStatus = null;

  const res = await provisionWithFailover({
    order: { public_id: 'ord_pl_failover', transport: 'tcp', duration_days: 30 },
    fetchFn: async (url) => {
      calledUrls.push(url);
      if (url.includes('192.0.2.1')) {
        throw new Error('AbortError: timeout after 3000ms');
      }
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            ok: true,
            sub_id: 'real_xui_sub_pl_554433',
            subscription_url: 'https://sub.example.com/json/real_xui_sub_pl_554433',
          };
        },
      };
    },
    updateOrderStatusFn: async (_id, st) => {
      finalStatus = st;
    },
    notifyAdminsFn: async () => {
      assert.fail('Admins should not be alerted when PL failover succeeds');
    },
  });

  assert.equal(calledUrls.length, 2);
  assert.match(calledUrls[0], /192\.0\.2\.1/);
  assert.match(calledUrls[1], /198\.51\.100\.1/);
  assert.equal(res.status, 'delivered');
  assert.equal(res.node, 'pl');
  assert.equal(res.sub_id, 'real_xui_sub_pl_554433');
  assert.equal(finalStatus, 'delivered');
});

test('Сценарий 3: Обе ноды (NL и PL) лежат -> заказ в pending_provision, алерт админам, НИКАКИХ фейковых ключей', async () => {
  let finalStatus = null;
  let adminAlert = null;

  const res = await provisionWithFailover({
    order: { public_id: 'ord_both_down', transport: 'tcp', duration_days: 30 },
    fetchFn: async (url) => {
      if (url.includes('192.0.2.1')) {
        throw new Error('ETIMEDOUT NL');
      }
      return { ok: false, status: 502, async json() { return {}; } };
    },
    updateOrderStatusFn: async (_id, st) => {
      finalStatus = st;
    },
    notifyAdminsFn: async (orderId, errText) => {
      adminAlert = { orderId, errText };
    },
  });

  assert.equal(finalStatus, 'pending_provision');
  assert.equal(res.status, 'pending_provision');
  assert.equal(res.sub_id, null, 'Fake sub_id must NEVER be generated when nodes are down');
  assert.equal(res.subscription_url, null, 'Fake subscription_url must NEVER be returned to customer');
  assert.ok(adminAlert, 'Admins must be notified');
  assert.equal(adminAlert.orderId, 'ord_both_down');
  assert.match(adminAlert.errText, /ETIMEDOUT NL/);
  assert.match(adminAlert.errText, /pl: HTTP 502/);
});
