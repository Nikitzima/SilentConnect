import { SETTINGS } from './config.js';

export function quotePrice(deviceLimit = 3, durationDays = 30, settings = SETTINGS) {
  const devicePrices = {
    3: settings.monthlyPrice3DevicesRub,
    6: settings.monthlyPrice6DevicesRub,
    9: settings.monthlyPrice9DevicesRub,
  };
  const limit = Number(deviceLimit) || 3;
  const days = Number(durationDays) || 30;
  const monthlyPrice = devicePrices[limit] ?? devicePrices[3] ?? 149;
  const months = Math.max(Math.floor(days / 30), 1);

  let discount = 0;
  if (days >= 360) {
    discount = 30;
  } else if (days >= 180) {
    discount = 20;
  } else if (days >= 90) {
    discount = 10;
  }

  const rawPrice = Math.floor((monthlyPrice * months * (100 - discount)) / 100);
  if (rawPrice <= 0) return 0;
  return Math.max(Math.floor((rawPrice + 5) / 10) * 10 - 1, 9);
}

export function calculateRenewalPrice(deviceLimit = 3, durationDays = 30, settings = SETTINGS) {
  return quotePrice(deviceLimit, durationDays, settings);
}

export function buildOffers(settings = SETTINGS) {
  const deviceLimits = [3, 6, 9];
  const durations = [
    [30, '1 месяц'],
    [90, '3 месяца'],
    [180, '6 месяцев'],
    [360, '12 месяцев'],
  ];
  const offers = {};
  for (const deviceLimit of deviceLimits) {
    for (const [durationDays, durationLabel] of durations) {
      const standardPrice = quotePrice(deviceLimit, durationDays, settings);
      offers[`tcp_${deviceLimit}_${durationDays}`] = {
        code: `tcp_${deviceLimit}_${durationDays}`,
        label: `Доступ на ${durationLabel}, до ${deviceLimit} устройств`,
        transport: 'tcp',
        durationDays,
        priceRub: standardPrice,
        deviceLimit,
        profileMode: 'anonymous',
        beta: false,
      };
      offers[`xhttp_${deviceLimit}_${durationDays}`] = {
        code: `xhttp_${deviceLimit}_${durationDays}`,
        label: `XHTTP доступ на ${durationLabel}, до ${deviceLimit} устройств`,
        transport: 'xhttp',
        durationDays,
        priceRub: standardPrice,
        deviceLimit,
        profileMode: 'anonymous',
        beta: false,
      };
      offers[`hybrid_${deviceLimit}_${durationDays}`] = {
        code: `hybrid_${deviceLimit}_${durationDays}`,
        label: `Доступ на ${durationLabel}, до ${deviceLimit} устройств`,
        transport: 'hybrid',
        durationDays,
        priceRub: standardPrice,
        deviceLimit,
        profileMode: 'anonymous',
        beta: false,
      };
    }
  }
  offers['tcp_30'] = offers['tcp_3_30'];
  offers['xhttp_30'] = offers['xhttp_3_30'];
  return offers;
}
