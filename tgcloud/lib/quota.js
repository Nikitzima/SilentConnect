import { nowTs } from './security.js';

export const CYCLE_SECONDS = 30 * 86400;

function formatDateUtc(tsSeconds) {
  const d = new Date(Number(tsSeconds) * 1000);
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  return `${dd}.${mm}.${yyyy}`;
}

export function getQuotaCycleInfo(profile, subscriptions = null, customNowTs = null) {
  const now = Number(customNowTs != null ? customNowTs : nowTs());
  if (!profile) {
    const nextTs = now + CYCLE_SECONDS;
    return {
      periodStartUtc: now,
      nextResetUtc: nextTs,
      cycleDays: 30,
      resetDateStr: formatDateUtc(nextTs),
      isPerpetual: false,
    };
  }

  const createdAt = Number(profile.createdAt ?? profile.created_at ?? now);
  const expiresAt = Number(profile.expiresAt ?? profile.expires_at ?? 0);

  let startTs = createdAt;
  if (Array.isArray(subscriptions) && subscriptions.length > 0) {
    const validStarts = subscriptions
      .map((s) => Number(s.createdAt ?? s.created_at ?? s.purchased_at ?? 0))
      .filter((v) => v > 0);
    if (validStarts.length > 0) {
      startTs = Math.min(...validStarts);
    }
  }

  if (startTs <= 0 || startTs > now) {
    startTs = now;
  }

  const elapsed = Math.max(0, now - startTs);
  const cyclesPassed = Math.floor(elapsed / CYCLE_SECONDS);
  const nextResetUtc = startTs + (cyclesPassed + 1) * CYCLE_SECONDS;
  const isPerpetual = Boolean(expiresAt > now && expiresAt - now > 365 * 10 * 86400);

  return {
    periodStartUtc: startTs,
    nextResetUtc,
    cycleDays: 30,
    resetDateStr: formatDateUtc(nextResetUtc),
    isPerpetual,
  };
}
