import { EndpointError } from 'sdk';
import { ShopBot } from '../lib/bot.js';
import { quotePrice } from '../lib/catalog.js';
import { nowTs } from '../lib/security.js';

export default async function (input, ctx) {
  const user = ctx.initData?.user;
  if (!user || !user.id) {
    throw new EndpointError('UNAUTHORIZED', { message: 'Missing validated Telegram user' });
  }

  const bot = new ShopBot();
  const chatId = String(user.id);
  await bot.store.upsertTelegramUser({ user, chatId });

  const action = String(input?.action || 'status');

  // 1. Получение статуса подписки и тарифов для Mini App (index.html)
  if (action === 'status') {
    const profile = await bot._activeProfileForChat(chatId, user);
    let subscriptionUrl = null;
    if (profile) {
      try {
        const rec = await bot._recoverSubscriptionForProfile(profile.public_id);
        subscriptionUrl = rec.subscription_url;
      } catch (_) {
        // ignore
      }
    }
    return {
      user: {
        id: user.id,
        username: user.username || null,
        firstName: user.first_name || '',
      },
      activeProfile: profile
        ? {
            publicId: profile.public_id,
            expiresAt: profile.expires_at,
            deviceLimit: profile.device_limit,
            subscriptionUrl,
          }
        : null,
      pricing: {
        3: { 30: quotePrice(3, 30), 90: quotePrice(3, 90), 180: quotePrice(3, 180), 360: quotePrice(3, 360) },
        6: { 30: quotePrice(6, 30), 90: quotePrice(6, 90), 180: quotePrice(6, 180), 360: quotePrice(6, 360) },
        9: { 30: quotePrice(9, 30), 90: quotePrice(9, 90), 180: quotePrice(9, 180), 360: quotePrice(9, 360) },
      },
    };
  }

  // 2. Проверка промокода из Mini App
  if (action === 'check_promo') {
    const code = String(input?.promo || '').trim();
    if (!code) {
      throw new EndpointError('EMPTY_PROMO', { message: 'Введите промокод' });
    }
    const promo = await bot.store.findValidPromo(code);
    if (!promo) {
      throw new EndpointError('INVALID_PROMO', { message: 'Промокод не найден или истёк' });
    }
    return {
      valid: true,
      promoType: promo.promo_type,
      discountPercent: promo.discount_percent,
      fixedPriceRub: promo.fixed_price_rub,
      durationDays: promo.duration_days,
      deviceLimit: promo.device_limit,
    };
  }

  // 3. Создание заказа из Mini App с мгновенной выдачей ссылки Platega
  if (action === 'create_order') {
    const devices = [3, 6, 9].includes(Number(input?.devices)) ? Number(input.devices) : 3;
    const months = [1, 3, 6, 12].includes(Number(input?.months)) ? Number(input.months) : 1;
    const durationDays = months * 30;
    const email = String(input?.email || '').trim();
    const promoCode = String(input?.promo || '').trim();

    const basePrice = quotePrice(devices, durationDays);
    let finalPrice = basePrice;
    let promoId = null;

    if (promoCode) {
      const promo = await bot.store.findValidPromo(promoCode);
      if (promo && promo.promo_type === 'discount') {
        promoId = promo.id;
        finalPrice = Math.max(Math.floor((basePrice * (100 - Number(promo.discount_percent))) / 100), 0);
      }
    }

    const order = await bot.store.createOrder({
      kind: 'purchase',
      status: finalPrice > 0 ? 'waiting_payment' : 'auto_provision',
      transport: 'tcp',
      durationDays,
      profileMode: 'anonymous',
      basePriceRub: basePrice,
      finalPriceRub: finalPrice,
      promoId,
      customerChatId: chatId,
      customerEmail: email,
      meta: { source: `miniapp_tcp_${devices}_${durationDays}`, device_limit: devices },
    });

    if (finalPrice === 0) {
      const res = await bot.completeOrder(order, 'miniapp-free-promo');
      return {
        status: 'delivered',
        orderPublicId: order.public_id,
        subscriptionUrl: res.subscription_url,
      };
    }

    const paymentUrl = await bot.getOrCreatePlategaPaymentUrl(order);
    await bot.notifyAdminsAboutOrder(order);
    return {
      status: 'waiting_payment',
      orderPublicId: order.public_id,
      finalPriceRub: finalPrice,
      paymentUrl,
    };
  }

  // 4. Проверка оплаты заказа из Mini App
  if (action === 'check_order') {
    const orderPublicId = String(input?.orderPublicId || '').trim();
    const order = await bot.store.getOrder(orderPublicId);
    if (!order || String(order.customer_chat_id) !== chatId) {
      throw new EndpointError('ORDER_NOT_FOUND', { message: 'Заказ не найден' });
    }
    if (order.status === 'delivered') {
      const res = await bot._recoverSubscriptionForOrder(order);
      return { status: 'delivered', subscriptionUrl: res.subscription_url };
    }
    const txId = String(order.meta_json?.platega_transaction_id || '').trim();
    if (txId && bot.platega.isConfigured) {
      const txStatus = await bot.platega.getTransactionStatus(txId, true);
      if (String(txStatus.status || '').toUpperCase() === 'CONFIRMED') {
        const meta = { ...(order.meta_json || {}), platega_confirmed_at: nowTs() };
        await bot.store.updateOrderMeta(order.public_id, meta);
        const res = await bot.completeOrder(order, 'miniapp_check_payment');
        return { status: 'delivered', subscriptionUrl: res.subscription_url };
      }
    }
    return { status: order.status };
  }

  throw new EndpointError('UNKNOWN_ACTION', { action });
}
