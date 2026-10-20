import { ShopBot } from '../lib/bot.js';

export default async function (callbackQuery, ctx) {
  if (!callbackQuery || !callbackQuery.id) return;
  const bot = new ShopBot();
  await bot.handleCallback(callbackQuery);
}
