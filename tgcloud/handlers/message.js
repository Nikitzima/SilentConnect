import { ShopBot } from '../lib/bot.js';

export default async function (message, ctx) {
  if (!message || !message.chat) return;
  const bot = new ShopBot();
  await bot.handleMessage(message);
}
