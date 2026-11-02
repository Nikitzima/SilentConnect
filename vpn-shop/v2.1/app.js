/* =========================================================================
   SilentConnect Redesign v2 — Полная экосистема (1:1 с боевым сайтом):
   - Liquid Glass Segmented Controls с пружинной физикой перетаскивания (lift/drag/squash)
   - Анимированный пересчёт цифр (requestAnimationFrame) + Spotlight (.spot)
   - Интуитивная зона финальной цены (Итого к оплате + Старая цена + % скидки + ₽/мес + Выгода)
   - Автоскрытие мобильной панели .mbar при видимости #checkout
   - Полный блок FAQ + Все 5 экранов + Все модалки + Command Palette (⌘K)
   ========================================================================= */

(() => {
'use strict';

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const fmt = n => new Intl.NumberFormat('ru-RU').format(Math.round(n));

let SUB_ID = 'sc_live_88f29a1d';
let SUB_URL = `https://sub.silentconnect.net/my-secret-sub/${SUB_ID}`; /* PLACEHOLDER */
let SUB_IMPORT_URL = `https://sub.silentconnect.net/my-secret-sub/import/${SUB_ID}`; /* PLACEHOLDER */
let IMPORT_BASE = 'https://sub.silentconnect.net/my-secret-sub/import'; /* PLACEHOLDER */
let APP_IMPORT_URLS = {};
const importUrlFor = app => APP_IMPORT_URLS[app] || `${IMPORT_BASE}/${app}/${SUB_ID}`;

/* ---------- Всплывающие уведомления (Toast) ---------- */
let toastTimer = null;
function toast(msg, duration = 3000) {
  const t = $('#toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), duration);
}
window.toast = toast;

/* ---------- Копирование в буфер обмена ---------- */
function copyToClipboard(text, successMsg = 'Скопировано в буфер обмена') {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
      .then(() => toast(successMsg))
      .catch(() => fallbackCopy(text, successMsg));
  } else {
    fallbackCopy(text, successMsg);
  }
}
window.copyToClipboard = copyToClipboard;

function fallbackCopy(text, successMsg) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    toast(successMsg);
  } catch (err) {
    toast('Не удалось скопировать. Скопируйте вручную.');
  }
  document.body.removeChild(ta);
}

/* Обработка глобальных кликов по [data-copy-url], [data-toast], .cf-widget */
document.addEventListener('click', e => {
  const copyBtn = e.target.closest('[data-copy-url]');
  if (copyBtn) {
    e.preventDefault();
    copyToClipboard(copyBtn.dataset.copyUrl, 'Ссылка подписки скопирована!');
    return;
  }
  const toastBtn = e.target.closest('[data-toast]');
  if (toastBtn) {
    const row = toastBtn.closest('.copy-row');
    const inp = row ? $('input', row) : null;
    if (inp && inp.value) copyToClipboard(inp.value, toastBtn.dataset.toast);
    else toast(toastBtn.dataset.toast);
  }
  const cf = e.target.closest('.cf-widget');
  if (cf) {
    const cur = cf.getAttribute('data-checked') === 'true';
    cf.setAttribute('data-checked', String(!cur));
    cf.setAttribute('aria-checked', String(!cur));
  }
});

/* ---------- Spotlight (.spot) курсорное свечение на ПК ---------- */
if (window.matchMedia('(pointer: fine)').matches) {
  document.addEventListener('pointermove', e => {
    const card = e.target.closest && e.target.closest('.spot');
    if (!card) return;
    const r = card.getBoundingClientRect();
    card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
    card.style.setProperty('--my', (e.clientY - r.top) + 'px');
  }, { passive: true });
}

/* ---------- Генератор SVG QR-кода ---------- */
function renderSvgQr(text, containerEl, size = 164) {
  if (!containerEl) return;
  let hash = 0;
  for (let i = 0; i < text.length; i++) hash = ((hash << 5) - hash) + text.charCodeAt(i) | 0;
  const dim = 25;
  const cellSize = size / dim;
  let paths = '';

  function drawFinder(ox, oy) {
    paths += `<rect x="${ox * cellSize}" y="${oy * cellSize}" width="${7 * cellSize}" height="${7 * cellSize}" fill="#fff" rx="3"/>`;
    paths += `<rect x="${(ox + 1) * cellSize}" y="${(oy + 1) * cellSize}" width="${5 * cellSize}" height="${5 * cellSize}" fill="#080e0c"/>`;
    paths += `<rect x="${(ox + 2) * cellSize}" y="${(oy + 2) * cellSize}" width="${3 * cellSize}" height="${3 * cellSize}" fill="#34e3a4" rx="2"/>`;
  }
  drawFinder(1, 1);
  drawFinder(dim - 8, 1);
  drawFinder(1, dim - 8);

  for (let r = 0; r < dim; r++) {
    for (let c = 0; c < dim; c++) {
      if ((r < 9 && c < 9) || (r < 9 && c >= dim - 9) || (r >= dim - 9 && c < 9)) continue;
      const bit = ((hash ^ (r * 31 + c * 17)) & (1 << ((r + c) % 8))) !== 0;
      if (bit) {
        paths += `<rect x="${c * cellSize}" y="${r * cellSize}" width="${cellSize * 0.9}" height="${cellSize * 0.9}" fill="#34e3a4" rx="1.5" opacity="0.9"/>`;
      }
    }
  }

  containerEl.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="display:block;margin:0 auto">${paths}</svg>`;
}

/* ---------- Навигация & Автоскрытие нижней панели .mbar у чекаута ---------- */
const navEl = $('#nav');
function syncNavScroll() {
  if (navEl) navEl.classList.toggle('solid', window.scrollY > 20);
}
window.addEventListener('scroll', syncNavScroll, { passive: true });
syncNavScroll();

const mbarEl = $('#mbar');
const checkoutEl = $('#checkout');
if (mbarEl && checkoutEl && 'IntersectionObserver' in window) {
  new IntersectionObserver(entries => {
    mbarEl.classList.toggle('hide-bar', entries[0].isIntersecting);
  }, { threshold: 0.12 }).observe(checkoutEl);
}

/* ---------- Drag-to-scroll для горизонтальных вкладок ---------- */
function setupDraggableTrack(track) {
  if (!track || track._dragInit) return;
  track._dragInit = true;
  let isDown = false, startX = 0, scrollLeft = 0, moved = false;
  track.addEventListener('mousedown', e => {
    isDown = true;
    startX = e.pageX - track.offsetLeft;
    scrollLeft = track.scrollLeft;
    moved = false;
  });
  window.addEventListener('mouseup', () => { isDown = false; });
  track.addEventListener('mousemove', e => {
    if (!isDown) return;
    e.preventDefault();
    const x = e.pageX - track.offsetLeft;
    const walk = (x - startX) * 1.5;
    if (Math.abs(walk) > 4) moved = true;
    track.scrollLeft = scrollLeft - walk;
  });
  track.addEventListener('click', e => {
    if (moved) { e.preventDefault(); e.stopPropagation(); }
  }, true);
}

function centerActiveTab(track) {
  if (!track) return;
  const act = track.querySelector('.active') || track.querySelector('.on');
  if (act && track.scrollWidth > track.clientWidth) {
    const targetLeft = Math.max(0, Math.min(track.scrollWidth - track.clientWidth, act.offsetLeft - (track.clientWidth - act.offsetWidth) / 2));
    if (Math.abs(track.scrollLeft - targetLeft) > 3) {
      track.scrollTo({ left: targetLeft, behavior: 'smooth' });
    }
  }
}

/* =========================================================================
   1. ПЛАТФОРМЫ И АВТООПРЕДЕЛЕНИЕ (subjson-service/app.py)
   ========================================================================= */
const OS_META = (window.SC_OS && window.SC_OS.length) ? window.SC_OS : [
  { id: 'ios', label: 'iOS', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29 .87 .78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.64 1.36-.57.65-1.07 1.72-.94 2.74 1.01.08 2.04-.5 2.66-1.25z"/></svg>' },
  { id: 'android', label: 'Android', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></svg>' },
  { id: 'windows', label: 'Windows', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M0 3.45L9.75 2.1v9.45H0m10.95-9.6L24 0v11.4H10.95M0 12.6h9.75v9.45L0 20.7M10.95 12.6H24V24l-13.05-1.8"/></svg>' },
  { id: 'macos', label: 'macOS', svg: '<svg viewBox="0 0 512 512" width="18" height="18"><rect width="512" height="512" fill="#dbe9f4" rx="85"/><path fill="#1e73f2" d="m0 0h262q-65 162-64 286c0 7 6 13 13 13h64q-6 113 28 213H0z"/></svg>' },
  { id: 'linux', label: 'Linux', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="12" r="9"/></svg>' },
  { id: 'androidtv', label: 'Android TV', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M22 3H2c-.6 0-1 .4-1 1v13c0 .6.4 1 1 1h8v1.5H7c-.3 0-.5.2-.5.5s.2.5.5.5h10c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-3V18h8c.6 0 1-.4 1-1V4c0-.6-.4-1-1-1zm-.2 13.8H2.2V4.2h19.6v12.6z"/></svg>' },
  { id: 'appletv', label: 'Apple TV', svg: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M22 3H2c-.6 0-1 .4-1 1v13c0 .6.4 1 1 1h8v1.5H7c-.3 0-.5.2-.5.5s.2.5.5.5h10c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-3V18h8c.6 0 1-.4 1-1V4c0-.6-.4-1-1-1zm-.2 13.8H2.2V4.2h19.6v12.6z"/></svg>' }
];
const OS_LABEL = {};
OS_META.forEach(o => { OS_LABEL[o.id] = o.label; });

function detectPlatform() {
  const ua = navigator.userAgent || '';
  const pf = navigator.platform || '';
  if (/iPad|iPhone|iPod/i.test(ua)) return 'ios';
  if (/Android/i.test(ua)) return /TV|AFT|BRAVIA|SMART-TV/i.test(ua) ? 'androidtv' : 'android';
  if (/Windows/i.test(ua)) return 'windows';
  if (/Mac/i.test(pf)) return 'macos';
  if (/Linux/i.test(pf)) return 'linux';
  return 'windows';
}
const detectedOs = detectPlatform();
['detectedOsMain', 'detectedOsAwg', 'detectedOsOf'].forEach(id => {
  const el = $('#' + id);
  if (el) el.textContent = OS_LABEL[detectedOs] || detectedOs;
});

/* =========================================================================
   2. ТАРИФНЫЙ КАЛЬКУЛЯТОР И ОФОРМЛЕНИЕ ЗАКАЗА (vpn_shop/catalog.py)
   ========================================================================= */
const CFG = {
  names:  { 3: 'Личный', 6: 'Домашний', 9: 'Расширенный' },
  awg:    { 3: 250, 6: 500, 9: 1000 },
  prices: { 3: { 1: 149, 3: 399, 6: 719, 12: 1249 },
            6: { 1: 199, 3: 539, 6: 959, 12: 1669 },
            9: { 1: 239, 3: 629, 6: 1129, 12: 1969 } },
  label:  { 1: '1 мес', 3: '3 мес', 6: '6 мес', 12: '12 мес' },
  full:   { 1: '1 месяц', 3: '3 месяца', 6: '6 месяцев', 12: '12 месяцев' },
  days:   { 1: 30, 3: 90, 6: 180, 12: 360 }
};

const refParam = new URLSearchParams(location.search).get('ref') || '';
const S = {
  dev: 3, months: 6, promo: '', promoType: null, promoPct: 0,
  refPct: refParam.startsWith('ref_') ? 10 : 0,
  renDev: 6, renMonths: 6, emailBound: true, bindOnly: false,
  subMode: 'main',
  osMain: detectedOs, appMain: 'incy',
  osAwg: (detectedOs === 'appletv' || detectedOs === 'androidtv') ? 'windows' : detectedOs, appAwg: 'amneziavpn',
  osOf: (detectedOs === 'androidtv' || detectedOs === 'appletv') ? 'ios' : detectedOs,
  ofState: 'active', ofCountry: 'nl', ofTargetCountry: 'pl',
  awgTargetSlot: 1
};

if (S.refPct > 0 && $('#refBanner')) $('#refBanner').hidden = false;
if ($('#refClear')) {
  $('#refClear').addEventListener('click', () => {
    S.refPct = 0;
    if ($('#refBanner')) $('#refBanner').hidden = true;
    renderCatalog();
    toast('Реферальная скидка сброшена');
  });
}

/* Плавный анимированный счётчик цифр */
const numReg = new WeakMap();
function num(el, target, suffix = '', dur = 380) {
  if (!el) return;
  let r = numReg.get(el);
  if (!r) {
    const parsed = parseFloat(String(el.textContent).replace(/[^\d.-]/g, ''));
    const initial = !isNaN(parsed) ? parsed : target;
    r = { v: initial, raf: 0 };
    numReg.set(el, r);
  }
  cancelAnimationFrame(r.raf);
  const from = r.v;
  if (Math.round(from) === Math.round(target)) {
    r.v = target;
    el.textContent = fmt(target) + suffix;
    return;
  }
  const t0 = performance.now();
  const step = now => {
    const k = Math.min(1, (now - t0) / dur);
    const e = 1 - Math.pow(1 - k, 4);
    r.v = from + (target - from) * e;
    el.textContent = fmt(r.v) + suffix;
    if (k < 1) r.raf = requestAnimationFrame(step);
  };
  r.raf = requestAnimationFrame(step);
}

function calc(dev, m) {
  const base = CFG.prices[dev][1] * m;
  const cat  = CFG.prices[dev][m];
  const extra = Math.max(S.promoPct, S.refPct);
  const total = S.promoType === 'gift' ? 0 : Math.floor(cat * (100 - extra) / 100);
  return {
    base,
    total,
    per: Math.round(total / m),
    saved: Math.max(base - total, 0),
    pct: base ? Math.round((1 - total / base) * 100) : 0,
    catPct: Math.round((1 - cat / base) * 100)
  };
}

/* Генерация плиток сроков в #tiles */
const tilesEl = $('#tiles');
if (tilesEl) {
  tilesEl.innerHTML = '';
  [1, 3, 6, 12].forEach(m => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'tile';
    b.setAttribute('role', 'radio');
    b.dataset.m = String(m);
    b.innerHTML = `
      <div class="tile-top"><span class="tile-name">${CFG.label[m]}</span><span class="save" hidden></span></div>
      <div class="tile-price"><b class="tab t-per">0</b><span>₽/мес</span></div>
      <div class="tile-total"><b class="tab t-tot">0</b> ₽ всего</div>`;
    b.addEventListener('click', () => {
      S.months = m;
      renderCatalog();
    });
    tilesEl.appendChild(b);
  });
}

/* Универсальная пружинная физика перетаскивания для Liquid Glass Segmented Control */
function bindLiquidSegmented(segEl, getIndexFn, onSelectIdxFn) {
  if (!segEl) return () => {};
  const btns = $$('.seg-btn', segEl);
  let squashTimer = null;
  let down = null;

  function setVisual(index, squash = true) {
    segEl.style.setProperty('--i', index);
    btns.forEach((b, k) => b.setAttribute('aria-checked', String(k === index)));
    if (squash) {
      segEl.classList.add('squash');
      clearTimeout(squashTimer);
      squashTimer = setTimeout(() => segEl.classList.remove('squash'), 220);
    }
  }

  const slotW = () => (segEl.clientWidth - 10) / 3;

  segEl.addEventListener('pointerdown', e => {
    if (e.button !== 0 && e.pointerType === 'mouse') return;
    down = { x: e.clientX, i: getIndexFn(), moved: false, id: e.pointerId, dx: 0 };
    segEl.classList.add('lift');
  });

  segEl.addEventListener('pointermove', e => {
    if (!down) return;
    const dx = e.clientX - down.x;
    if (!down.moved && Math.abs(dx) > 5) {
      down.moved = true;
      segEl.classList.add('drag');
      if (segEl.setPointerCapture) {
        try { segEl.setPointerCapture(down.id); } catch (_) {}
      }
    }
    if (!down.moved) return;
    const base = down.i * slotW();
    const target = Math.min(Math.max(base + dx, 0), 2 * slotW());
    down.dx = target - base;
    segEl.style.setProperty('--dx', down.dx + 'px');
  });

  const endDrag = e => {
    if (!down) return;
    const d = down;
    down = null;
    segEl.classList.remove('lift', 'drag');
    let idx = d.i;
    if (d.moved) {
      idx = Math.round((d.i * slotW() + d.dx) / slotW());
    } else if (e && e.target && e.target.closest) {
      const b = e.target.closest('.seg-btn');
      if (b) idx = btns.indexOf(b);
    }
    idx = Math.min(2, Math.max(0, idx));
    segEl.style.setProperty('--dx', '0px');
    onSelectIdxFn(idx);
  };

  segEl.addEventListener('pointerup', endDrag);
  segEl.addEventListener('pointercancel', () => {
    down = null;
    segEl.classList.remove('lift', 'drag');
    segEl.style.setProperty('--dx', '0px');
  });

  btns.forEach((b, k) => b.addEventListener('click', () => onSelectIdxFn(k)));
  return setVisual;
}

const DEVS = [3, 6, 9];
const setDevSeg = bindLiquidSegmented(
  $('#devSeg'),
  () => DEVS.indexOf(S.dev),
  idx => {
    const next = DEVS[idx];
    const changed = next !== S.dev;
    S.dev = next;
    setDevSeg(idx, changed);
    renderCatalog();
  }
);

/* Отрисовка витрины и понятной зоны финальной цены */
function renderCatalog() {
  const plan = CFG.names[S.dev];
  const cur = calc(S.dev, S.months);
  const devIdx = DEVS.indexOf(S.dev);
  setDevSeg(devIdx >= 0 ? devIdx : 0, false);

  if (tilesEl) {
    $$('.tile', tilesEl).forEach(t => {
      const m = Number(t.dataset.m);
      const c = calc(S.dev, m);
      t.setAttribute('aria-checked', String(m === S.months));
      num($('.t-per', t), c.per);
      num($('.t-tot', t), c.total);
      const sv = $('.save', t);
      if (sv) {
        if (c.catPct > 0) { sv.hidden = false; sv.textContent = `−${c.catPct}%`; }
        else { sv.hidden = true; }
      }
    });
  }

  num($('#awgQ'), CFG.awg[S.dev], ' ГБ');

  const coPlan = $('#coPlan');
  if (coPlan) coPlan.textContent = `Тариф «${plan}» · ${CFG.full[S.months]}`;

  const coPctBadge = $('#coPctBadge');
  if (coPctBadge) {
    coPctBadge.hidden = cur.pct <= 0;
    coPctBadge.textContent = S.promoType === 'gift' ? 'ПОДАРОК −100%' : `−${cur.pct}%`;
  }

  num($('#coPrice'), cur.total);

  const coOld = $('#coOld');
  if (coOld) {
    coOld.textContent = cur.saved > 0 ? `${fmt(cur.base)} ₽` : '';
    coOld.hidden = cur.saved <= 0;
  }

  const coMonthVal = $('#coMonthVal') || $('#coMonth');
  if (coMonthVal) {
    if (S.promoType === 'gift') {
      coMonthVal.textContent = '0';
    } else {
      num(coMonthVal, cur.per, '', 320);
    }
  }

  const coSaveRow = $('#coSaveRow');
  const coSave = $('#coSave');
  const coSavePrefix = $('#coSavePrefix');
  const coSaveVal = $('#coSaveVal');
  const coSaveSuffix = $('#coSaveSuffix');
  if (coSaveRow && coSave) {
    if (S.promoType === 'gift') {
      coSaveRow.hidden = false;
      if (coSavePrefix) coSavePrefix.textContent = 'бесплатно по коду (';
      if (coSaveVal) num(coSaveVal, cur.base, '', 320);
      if (coSaveSuffix) coSaveSuffix.textContent = ' ₽)';
    } else if (S.promoPct > 0) {
      coSaveRow.hidden = false;
      if (coSavePrefix) coSavePrefix.textContent = 'экономия ';
      if (coSaveVal) num(coSaveVal, cur.saved, '', 320);
      if (coSaveSuffix) coSaveSuffix.textContent = ` ₽ (промокод −${S.promoPct}%)`;
    } else if (S.refPct > 0) {
      coSaveRow.hidden = false;
      if (coSavePrefix) coSavePrefix.textContent = 'экономия ';
      if (coSaveVal) num(coSaveVal, cur.saved, '', 320);
      if (coSaveSuffix) coSaveSuffix.textContent = ` ₽ (приглашение −${S.refPct}%)`;
    } else if (cur.saved > 0) {
      coSaveRow.hidden = false;
      if (coSavePrefix) coSavePrefix.textContent = 'экономия ';
      if (coSaveVal) num(coSaveVal, cur.saved, '', 320);
      if (coSaveSuffix) coSaveSuffix.textContent = ' ₽';
    } else {
      coSaveRow.hidden = true;
    }
  }

  const fOffer = $('#fOffer');
  if (fOffer) fOffer.value = `tcp_${S.dev}_${CFG.days[S.months]}`;

  const mbPlan = $('#mbPlan');
  if (mbPlan) mbPlan.textContent = `${plan} · ${CFG.label[S.months]}`;
  const mbPrice = $('#mbPrice');
  if (mbPrice) mbPrice.textContent = `${fmt(cur.total)} ₽`;
}
window.renderCatalog = renderCatalog;

/* Промокоды с плавной аккордеон-анимацией */
const promoToggle = $('#promoToggle');
const promoBoxWrap = $('#promoBoxWrap');
const promoCaret = $('#promoCaret');
if (promoToggle && promoBoxWrap) {
  promoToggle.addEventListener('click', () => {
    const isOpen = promoBoxWrap.classList.contains('open');
    promoBoxWrap.classList.toggle('open', !isOpen);
    promoToggle.setAttribute('aria-expanded', String(!isOpen));
    if (promoCaret) promoCaret.style.transform = !isOpen ? 'rotate(180deg)' : '';
    if (!isOpen) {
      const pInput = $('#promo');
      if (pInput) setTimeout(() => pInput.focus(), 160);
    }
  });
}

const promoInput = $('#promo');
const promoApplyBtn = $('#promoApply');
const promoMsg = $('#promoMsg');

function applyPromo() {
  if (!promoInput) return;
  const code = promoInput.value.trim().toUpperCase();
  if (!code) {
    S.promo = ''; S.promoPct = 0; S.promoType = null;
    if (promoMsg) { promoMsg.className = 'promo-msg'; promoMsg.textContent = 'Примеры для теста: WELCOME10, SALE20 или подарочный GIFT30.'; }
    renderCatalog();
    return;
  }
  if (code === 'WELCOME10' || code === 'TEST10') {
    S.promo = code; S.promoPct = 10; S.promoType = 'pct';
    if (promoMsg) { promoMsg.className = 'promo-msg ok'; promoMsg.textContent = `✓ Промокод ${code} применён (−10%)`; }
    toast(`Промокод ${code} применён!`);
  } else if (code === 'SALE20' || code === 'START') {
    S.promo = code; S.promoPct = 20; S.promoType = 'pct';
    if (promoMsg) { promoMsg.className = 'promo-msg ok'; promoMsg.textContent = `✓ Промокод ${code} применён (−20%)`; }
    toast(`Промокод ${code} применён!`);
  } else if (code === 'GIFT30' || code === 'FREE') {
    S.promo = code; S.promoPct = 100; S.promoType = 'gift';
    if (promoMsg) { promoMsg.className = 'promo-msg ok'; promoMsg.textContent = '✓ Подарочный сертификат активирован (100% скидка)'; }
    toast('Подарочный сертификат применён!');
  } else {
    S.promo = ''; S.promoPct = 0; S.promoType = null;
    if (promoMsg) { promoMsg.className = 'promo-msg err'; promoMsg.textContent = '✕ Промокод не найден или устарел'; }
    toast('Промокод не найден');
  }
  renderCatalog();
}
if (promoApplyBtn) promoApplyBtn.addEventListener('click', applyPromo);
if (promoInput) promoInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); applyPromo(); } });

renderCatalog();

/* =========================================================================
   3. FAQ (Заполнение и интерактивный аккордеон)
   ========================================================================= */
const FAQ_DATA = [
  {
    q: 'Как подключиться за 2 минуты (3 простых шага)?',
    a: '<b>1. Оформите тариф:</b> выберите количество устройств и срок — персональная ссылка появится сразу после подтверждения оплаты.<br><br><b>2. Откройте мастер настройки:</b> ссылка автоматически определит ваше устройство и предложит проверенное приложение в один клик под вашу операционную систему (iOS, Android, Windows или macOS).<br><br><b>3. Нажмите «Подключить»:</b> профиль импортируется в один клик. Перенастраивать вручную ничего не потребуется.'
  },
  {
    q: 'Сохраняется ли история посещений и сетевые логи?',
    a: 'Нет. Мы придерживаемся строгой политики <b>No-Logs</b>. На серверах полностью отключена запись истории посещаемых сайтов (access-логи), DNS-запросов и сетевых маршрутов. Временные системные журналы автоматически очищаются. Для работы подписки хранится только привязанный Email, дата окончания тарифа и счётчик израсходованного объёма.'
  },
  {
    q: 'Действительно ли трафик и скорость безлимитны?',
    a: 'В <b>Основном профиле</b> гигабайты и скорость не ограничиваются — действует прозрачная политика добросовестного использования (Fair Use) для комфортного личного и семейного применения (4K-видео, стриминг, веб-серфинг, игры, загрузка файлов). Для выделенного игрового контура <b>AmneziaWG</b> (прямой UDP с минимальным пингом) предоставляется ежемесячный пакет скоростного трафика: <b>250 ГБ</b> (Личный), <b>500 ГБ</b> (Домашний) или <b>1 000 ГБ</b> (Расширенный).'
  },
  {
    q: 'Будет ли доступ к зарубежным сайтам, нейросетям и медиаплатформам?',
    a: 'Да. Сервис использует современные защищённые протоколы с интеллектуальной маршрутизацией через европейские узлы связи. Все популярные веб-ресурсы, зарубежные сайты, платформы искусственного интеллекта и сетевые сервисы открываются на максимальной скорости вашего интернет-канала.'
  },
  {
    q: 'На каких устройствах работает SilentConnect?',
    a: 'На любых: смартфонах и планшетах <b>iOS</b> (iPhone, iPad) и <b>Android</b>, компьютерах <b>Windows</b>, <b>macOS</b> и <b>Linux</b>, а также на <b>Android TV</b> и <b>Apple TV</b>. Мастер настройки сам подскажет оптимальное приложение под вашу операционную систему.'
  },
  {
    q: 'Зачем указывать Email при заказе?',
    a: 'На почту мы отправляем персональную ссылку доступа, чеки об оплате и напоминания до окончания срока подписки (без спама). По этой почте вы в любой момент сможете войти в личный кабинет с нового устройства и восстановить доступ.'
  },
  {
    q: 'Сколько устройств можно подключить одновременно?',
    a: 'В зависимости от тарифа — <b>3, 6 или 9 устройств</b> одновременно (смартфоны, ноутбуки, планшеты, ТВ). Каждое устройство подключается по своей ссылке или выделенному слоту конфигурации и работает независимо без конфликтов сессий.'
  },
  {
    q: 'Сохранится ли доступ при смене или сбросе телефона?',
    a: 'Да. Ваша ссылка подписки постоянная. При покупке нового устройства или сбросе настроек достаточно снова открыть ссылку из письма на почте или войти в личный кабинет на сайте по Email — все оплаченные дни сохранятся, повторно платить не нужно.'
  },
  {
    q: 'Нужно ли перенастраивать устройства при продлении?',
    a: 'Нет. При продлении тарифа новые дни автоматически суммируются с вашим текущим остатком. Ссылка и конфигурации на всех ваших смартфонах и компьютерах продолжают работать без каких-либо повторных настроек.'
  },
  {
    q: 'Что такое режим «Белые списки»?',
    a: 'В вашу подписку уже включён режим <b>«Белые списки» (OpenFlux)</b>. Он разработан для ситуаций, когда сеть работает в ограниченном режиме и пропускает трафик только по доверенным адресам. Соединение направляется через резервные защищённые шлюзы с выходом в Европе, позволяя оставаться на связи даже при изолированной или нестабильной сети.'
  },
  {
    q: 'Как работает гарантия возврата средств в течение 14 дней?',
    a: 'Для новых пользователей действует 100% гарантия возврата на первый заказ в течение <b>14 календарных дней</b> с момента оплаты (при расходе до 5 ГБ трафика в рамках Fair Use). Если на вашем провайдере сервис не подошёл и поддержка не смогла решить вопрос, напишите в @SilentConnectSupport — мы оформим возврат тем же способом (СБП или карта).'
  }
];

const faqListEl = $('#faqList');
if (faqListEl) {
  faqListEl.innerHTML = FAQ_DATA.map((item, idx) => `
    <div class="faq" data-open="${idx === 0 ? 'true' : 'false'}">
      <button type="button" class="faq-q" aria-expanded="${idx === 0 ? 'true' : 'false'}">
        <span>${item.q}</span>
        <i aria-hidden="true">+</i>
      </button>
      <div class="faq-a"><div><p>${item.a}</p></div></div>
    </div>
  `).join('');

  faqListEl.addEventListener('click', e => {
    const btn = e.target.closest('.faq-q');
    if (!btn) return;
    const faq = btn.closest('.faq');
    if (!faq) return;
    const isOpen = faq.getAttribute('data-open') === 'true';
    const currentOpen = faqListEl.querySelector('.faq[data-open="true"]');
    if (currentOpen && currentOpen !== faq) {
      currentOpen.setAttribute('data-open', 'false');
      const q = $('.faq-q', currentOpen);
      if (q) q.setAttribute('aria-expanded', 'false');
    }
    if (isOpen) {
      faq.setAttribute('data-open', 'false');
      btn.setAttribute('aria-expanded', 'false');
    } else {
      faq.setAttribute('data-open', 'true');
      btn.setAttribute('aria-expanded', 'true');
    }
  });
}

/* =========================================================================
   4. РОУТИНГ СТРАНИЦ / ЭКРАНОВ И СТРАНИЦА ЗАКАЗА
   ========================================================================= */
const TG_SVG = `<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true" style="flex-shrink:0"><path d="m20.665 3.717-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42 10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l-.313 4.674c.458 0 .66-.21.916-.458l2.198-2.137 4.572 3.377c.843.465 1.45.226 1.66-.782l3-14.126c.307-1.232-.469-1.789-1.277-1.421z"/></svg>`;
const TG_SUPPORT_URL = 'https://t.me/SilentConnectSupport';
const TG_BOT_SVG = `<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true" style="flex-shrink:0"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2.5C7.8 2.5 6 5.5 6 9.5V17c0 2.5 1.8 4.5 4.5 4.5h3c2.7 0 4.5-2 4.5-4.5V9.5C18 5.5 16.2 2.5 12 2.5zM8.4 10.8V9.5C8.4 7.2 9.8 5.2 12 5.2s3.6 2 3.6 4.3v1.3H8.4zM3.5 8.5C4.33 8.5 5 9.17 5 10v6c0 .83-.67 1.5-1.5 1.5S2 16.83 2 16v-6c0-.83.67-1.5 1.5-1.5zm17 0c.83 0 1.5.67 1.5 1.5v6c0 .83-.67 1.5-1.5 1.5s-1.5-.67-1.5-1.5v-6c0-.83.67-1.5 1.5-1.5z"/></svg>`;

function updateNavForView(name) {
  const navLinks = $('#navLinks') || $('.nav-links');
  const navActions = $('#navActions') || $('.nav-actions');
  if (!navLinks || !navActions) return;

  if (name === 'landing') {
    navLinks.innerHTML = `
      <a href="#tariffs" data-go="landing">Тарифы</a>
      <a href="#features" data-go="landing">Возможности</a>
      <a href="#faq" data-go="landing">Вопросы</a>
    `;
    navActions.innerHTML = `
      <button type="button" class="btn btn-ghost btn-sm" data-open-cabinet>Кабинет</button>
    `;
  } else if (name === 'sub') {
    navLinks.innerHTML = `
      <a href="#renewAcc" data-nav-action="renew">Продлить</a>
      <a href="#modeBar" data-nav-action="scroll">Режимы</a>
      <a href="#subViewport" data-nav-action="scroll">Инструкция</a>
    `;
    navActions.innerHTML = `
      <a class="btn btn-telegram btn-sm" href="${TG_SUPPORT_URL}" target="_blank" rel="noopener">${TG_SVG}<span>Поддержка</span></a>
      <button type="button" class="btn btn-ghost btn-sm hide-sm" data-open-cabinet>Кабинет</button>
    `;
  } else if (name === 'order') {
    navLinks.innerHTML = `
      <a href="#top" data-go="landing">← На главную</a>
    `;
    navActions.innerHTML = `
      <a class="btn btn-telegram btn-sm" href="${TG_SUPPORT_URL}" target="_blank" rel="noopener">${TG_SVG}<span>Поддержка</span></a>
    `;
  } else if (name === 'cabinet') {
    navLinks.innerHTML = `
      <a href="#top" data-nav-action="scroll">Мои подписки</a>
      <a href="#tariffs" data-go="landing">Оформить новую</a>
      <a href="#view-legal" data-go="legal">Документы</a>
    `;
    navActions.innerHTML = `
      <a class="btn btn-telegram btn-sm" href="${TG_SUPPORT_URL}" target="_blank" rel="noopener">${TG_SVG}<span>Поддержка</span></a>
    `;
  } else if (name === 'legal') {
    navLinks.innerHTML = `
      <a href="#top" data-go="landing">← На главную</a>
      <a href="#tariffs" data-go="landing">Тарифы</a>
    `;
    navActions.innerHTML = `
      <a class="btn btn-telegram btn-sm hide-sm" href="${TG_SUPPORT_URL}" target="_blank" rel="noopener">${TG_SVG}<span>Поддержка</span></a>
      <button type="button" class="btn btn-ghost btn-sm" data-open-cabinet>Кабинет</button>
    `;
  }
}

const VIEWS = ['landing', 'order', 'sub', 'cabinet', 'legal'];
function view(name, hash) {
  if (!VIEWS.includes(name)) name = 'landing';
  VIEWS.forEach(v => {
    const el = $('#view-' + v);
    if (el) el.hidden = v !== name;
  });
  $$('[data-page-tab]').forEach(b => b.classList.toggle('on', b.dataset.pageTab === name));
  if (mbarEl) mbarEl.style.display = name === 'landing' ? '' : 'none';

  updateNavForView(name);

  const target = hash && hash.length > 1 ? $(hash) : null;
  if (target) setTimeout(() => target.scrollIntoView({ behavior: 'smooth' }), 30);
  else window.scrollTo({ top: 0, behavior: 'auto' });
  syncNavScroll();
}
window.view = view;

$$('[data-page-tab]').forEach(b => b.addEventListener('click', () => view(b.dataset.pageTab)));
document.addEventListener('click', e => {
  const a = e.target.closest('[data-go]');
  if (!a) return;
  const href = a.getAttribute('href') || '';
  if (a.dataset.go === 'landing' && !$('#view-landing').hidden && href.startsWith('#')) {
    return;
  }
  e.preventDefault();
  closeAllModals();
  const doc = a.dataset.docLink;
  if (doc) showLegalDoc(doc);
  view(a.dataset.go, href.startsWith('#') ? href : '');
});

document.addEventListener('click', e => {
  const a = e.target.closest('[data-nav-action]');
  if (!a) return;
  e.preventDefault();
  const action = a.dataset.navAction;
  const href = a.getAttribute('href') || '';

  if (action === 'renew') {
    const doOpenRenew = () => {
      const el = $('#renewAcc');
      if (el) {
        if (typeof setRenewOpen === 'function') setRenewOpen(true);
        else if (window.setRenewOpen) window.setRenewOpen(true);
        else el.setAttribute('data-open', 'true');
        const headerOffset = 76;
        const elPos = el.getBoundingClientRect().top;
        const offsetPos = elPos + window.pageYOffset - headerOffset;
        window.scrollTo({ top: offsetPos, behavior: 'smooth' });
      }
    };
    if ($('#view-sub') && $('#view-sub').hidden) {
      view('sub');
      setTimeout(doOpenRenew, 60);
    } else {
      doOpenRenew();
    }
  } else if (action === 'scroll' && href && href.startsWith('#')) {
    if (href === '#top') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      const target = $(href);
      if (target) {
        const headerOffset = 76;
        const elPos = target.getBoundingClientRect().top;
        const offsetPos = elPos + window.pageYOffset - headerOffset;
        window.scrollTo({ top: offsetPos, behavior: 'smooth' });
      }
    }
  }
});

document.addEventListener('click', e => {
  const btn = e.target.closest('[data-open-cabinet]');
  if (!btn) return;
  e.preventDefault();
  openModal('cabinetModal');
});


function setOrderState(state) {
  if (!['waiting', 'delivered', 'cancelled'].includes(state)) state = 'waiting';
  if ($('#ordWait')) $('#ordWait').hidden = state !== 'waiting';
  if ($('#ordDone')) $('#ordDone').hidden = state !== 'delivered';
  if ($('#ordCancelled')) $('#ordCancelled').hidden = state !== 'cancelled';

  $$('[data-order-state]').forEach(b => b.classList.toggle('on', b.dataset.orderState === state));

  const badge = $('#ordBadge');
  if (badge) {
    if (state === 'waiting') { badge.className = 'status wait'; badge.innerHTML = '<i></i>Ожидает оплаты'; }
    else if (state === 'delivered') { badge.className = 'status ok'; badge.innerHTML = '<i></i>Оплачен'; }
    else { badge.className = 'status cancel'; badge.innerHTML = '<i></i>Отменён'; }
  }
}

$$('[data-order-state]').forEach(b => {
  b.addEventListener('click', () => {
    setOrderState(b.dataset.orderState);
    if (b.dataset.orderState === 'delivered') toast('✓ Оплата успешно подтверждена!');
  });
});

if ($('#payBtn')) {
  $('#payBtn').addEventListener('click', e => {
    e.preventDefault();
    toast('Подтверждение оплаты…');
    setTimeout(() => {
      setOrderState('delivered');
      toast('✓ Подписка активирована!');
    }, 450);
  });
}
if ($('#cancelOrdBtn')) {
  $('#cancelOrdBtn').addEventListener('click', () => {
    setOrderState('cancelled');
    toast('Заказ отменён');
  });
}

const orderForm = $('#orderForm');
if (orderForm) {
  orderForm.addEventListener('submit', e => {
    e.preventDefault();
    const emailField = $('#email');
    const email = (emailField ? emailField.value : '').trim();
    if (!email || !email.includes('@')) {
      if (emailField) emailField.classList.add('err');
      const err = $('#emailErr');
      if (err) err.hidden = false;
      toast('Укажите корректный Email для получения ключа');
      return;
    }
    const cur = calc(S.dev, S.months);
    if ($('#ordPlanName')) $('#ordPlanName').textContent = `${CFG.names[S.dev]} · до ${S.dev} устройств`;
    if ($('#ordDuration')) $('#ordDuration').textContent = `${CFG.days[S.months]} дней (${CFG.full[S.months]})`;
    if ($('#ordAwg')) $('#ordAwg').textContent = `${CFG.awg[S.dev]} ГБ в месяц`;
    if ($('#ordEmail')) $('#ordEmail').textContent = email;
    if ($('#ordTotal')) $('#ordTotal').textContent = `${fmt(cur.total)} ₽`;
    if ($('#payBtnSum')) $('#payBtnSum').textContent = `${fmt(cur.total)} ₽`;

    toast('Создание защищённого заказа…');
    setTimeout(() => {
      setOrderState(cur.total === 0 ? 'delivered' : 'waiting');
      view('order');
    }, 300);
  });
}
const emailInputEl = $('#email');
if (emailInputEl) {
  emailInputEl.addEventListener('input', () => {
    emailInputEl.classList.remove('err');
    const err = $('#emailErr');
    if (err) err.hidden = true;
  });
}

/* =========================================================================
   5. МАСТЕР ПОДКЛЮЧЕНИЯ: ОСНОВНОЙ РЕЖИМ (subjson-service/app.py)
   ========================================================================= */
const U = {
  HAPP_DOWNLOAD: 'https://www.happ.su/main',
  HAPP_IOS: 'https://apps.apple.com/us/app/happ-proxy-utility/id6504287215',
  HAPP_ANDROID: 'https://play.google.com/store/apps/details?id=com.happproxy',
  HAPP_APK: 'https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk',
  INCY_DOWNLOAD: 'https://incy.cc/#downloads',
  INCY_IOS: 'https://apps.apple.com/app/incy/id6756943388',
  INCY_ANDROID: 'https://play.google.com/store/apps/details?id=llc.itdev.incy',
  INCY_APK: 'https://github.com/INCY-DEV/incy-platforms/releases/download/latest/Incy.apk',
  INCY_WIN: 'https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-windows-setup.exe',
  INCY_MAC_DMG: 'https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-macos-arm64.dmg',
  INCY_LINUX: 'https://github.com/INCY-DEV/incy-platforms',
  STREISAND_IOS: 'https://apps.apple.com/us/app/streisand/id6450534064',
  STREISAND_MACOS: 'https://apps.apple.com/us/app/streisand/id6450534064',
  CLASH_MI_IOS: 'https://apps.apple.com/app/clash-mi/id6744321968',
  CLASH_DL: 'https://github.com/clash-verge-rev/clash-verge-rev/releases',
  CLASH_ANDROID: 'https://github.com/MetaCubeX/ClashMetaForAndroid/releases',
  V2RAYN_DL: 'https://github.com/2dust/v2rayN/releases',
  NEKOBOX_DL: 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases',
  V2RAYNG_DL: 'https://github.com/2dust/v2rayNG/releases',
  SINGBOX_IOS: 'https://apps.apple.com/app/sing-box-mt/id6785326793',
  SINGBOX_DL: 'https://github.com/SagerNet/sing-box/releases'
};
const dl = (label, url, icon) => ({ label, url, icon }); const ASSET_ROOT = window.SC_PROD ? '/assets/' : 'assets/';

const MAIN_APPS = [
  { id: 'happ', name: 'Happ', badge: '', icon: `${ASSET_ROOT}apps/happ.webp`,
    platforms: ['ios', 'android', 'windows', 'macos', 'linux', 'androidtv', 'appletv'],
    description: 'Флагманский клиент с поддержкой протоколов REALITY и XHTTP. Обеспечивает максимальную скорость и незаметность подключения на любых устройствах.',
    downloads: {
      ios: [dl('App Store', U.HAPP_IOS, 'appstore')],
      android: [dl('Google Play', U.HAPP_ANDROID, 'googleplay'), dl('Скачать APK (GitHub)', U.HAPP_APK, 'github')],
      windows: [dl('Официальный сайт (.exe)', U.HAPP_DOWNLOAD, 'globe')],
      macos: [dl('Официальный сайт (.dmg)', U.HAPP_DOWNLOAD, 'globe')],
      linux: [dl('Официальный сайт (.deb / AppImage)', U.HAPP_DOWNLOAD, 'globe')],
      androidtv: [dl('Google Play', U.HAPP_ANDROID, 'googleplay'), dl('Скачать APK (GitHub)', U.HAPP_APK, 'github')],
      appletv: [dl('App Store', U.HAPP_IOS, 'appstore')]
    } },
  { id: 'incy', name: 'INCY', badge: 'рекомендуем', icon: `${ASSET_ROOT}apps/incy.webp`,
    platforms: ['ios', 'android', 'windows', 'macos', 'linux', 'androidtv', 'appletv'],
    description: 'Современный клиент на базе Xray-core с нативной поддержкой REALITY, фрагментации TLS и умной маршрутизации трафика.',
    downloads: {
      ios: [dl('App Store', U.INCY_IOS, 'appstore')],
      android: [dl('Google Play', U.INCY_ANDROID, 'googleplay'), dl('Скачать APK (GitHub)', U.INCY_APK, 'github')],
      windows: [dl('GitHub (.exe)', U.INCY_WIN, 'github'), dl('Официальный сайт', U.INCY_DOWNLOAD, 'globe')],
      macos: [dl('Mac App Store', U.INCY_IOS, 'appstore'), dl('GitHub (.dmg)', U.INCY_MAC_DMG, 'github')],
      linux: [dl('GitHub (.deb / AppImage)', U.INCY_LINUX, 'github'), dl('Официальный сайт', U.INCY_DOWNLOAD, 'globe')],
      androidtv: [dl('Google Play', U.INCY_ANDROID, 'googleplay'), dl('Скачать APK (GitHub)', U.INCY_APK, 'github')],
      appletv: [dl('App Store', U.INCY_IOS, 'appstore')]
    } },
  { id: 'clash', name: 'Clash Mi / Mihomo', badge: '', icon: `${ASSET_ROOT}apps/clash.webp`, iosIcon: `${ASSET_ROOT}apps/clash_mi.webp`,
    platforms: ['windows', 'macos', 'android', 'linux', 'ios'],
    description: 'Мощный клиент с поддержкой умного авто-тестирования узлов и мгновенным переключением при сбоях.',
    downloads: {
      windows: [dl('GitHub Релизы (.exe)', U.CLASH_DL, 'github')],
      macos: [dl('GitHub Релизы (.dmg)', U.CLASH_DL, 'github')],
      android: [dl('GitHub Релизы (.apk)', U.CLASH_ANDROID, 'github')],
      linux: [dl('GitHub Релизы (.deb / AppImage)', U.CLASH_DL, 'github')],
      ios: [dl('App Store', U.CLASH_MI_IOS, 'appstore')]
    } },
  { id: 'v2rayn', name: 'v2rayN', badge: '', icon: `${ASSET_ROOT}apps/v2rayn.webp`,
    platforms: ['windows'],
    description: 'Популярный клиент для Windows с поддержкой Xray-ядра, автоматическим обновлением подписок и гибкой маршрутизацией.',
    downloads: { windows: [dl('GitHub Релизы (.zip)', U.V2RAYN_DL, 'github')] } },
  { id: 'nekobox', name: 'NekoBox', badge: '', icon: `${ASSET_ROOT}apps/nekobox.webp`,
    platforms: ['android'],
    description: 'Мощный и функциональный клиент для Android с поддержкой прямых JSON и Sing-box конфигураций.',
    downloads: { android: [dl('GitHub Релизы (.apk)', U.NEKOBOX_DL, 'github')] } },
  { id: 'v2rayng', name: 'v2rayNG', badge: '', icon: `${ASSET_ROOT}apps/v2rayng.webp`,
    platforms: ['android'],
    description: 'Классический проверенный клиент для Android для прямого импорта VLESS-конфигураций.',
    downloads: { android: [dl('GitHub Релизы (.apk)', U.V2RAYNG_DL, 'github')] } },
  { id: 'streisand', name: 'Streisand', badge: '', icon: `${ASSET_ROOT}apps/streisand.webp`,
    platforms: ['ios', 'macos'],
    description: 'Лёгкий и быстрый клиент, идеально оптимизированный под экосистемы iOS и macOS без расхода аккумулятора.',
    downloads: {
      ios: [dl('App Store', U.STREISAND_IOS, 'appstore')],
      macos: [dl('Mac App Store', U.STREISAND_MACOS, 'appstore')]
    } },
  { id: 'singbox', name: 'Sing-box', badge: '', icon: `${ASSET_ROOT}apps/singbox.webp`,
    platforms: ['ios', 'android', 'windows', 'macos', 'linux'],
    description: 'Универсальный сетевой клиент нового поколения с максимальной производительностью и нативной поддержкой Sing-box JSON.',
    downloads: {
      ios: [dl('App Store', U.SINGBOX_IOS, 'appstore')],
      android: [dl('GitHub Релизы (.apk)', U.SINGBOX_DL, 'github')],
      windows: [dl('GitHub Релизы (.zip)', U.SINGBOX_DL, 'github')],
      macos: [dl('GitHub Релизы (.dmg / .zip)', U.SINGBOX_DL, 'github')],
      linux: [dl('GitHub Релизы (.tar.gz)', U.SINGBOX_DL, 'github')]
    } }
];

function usageText(appId, os) {
  const map = {
    happ: 'Запустите Happ и нажмите большую центральную кнопку включения. При первом запуске разрешите системе добавление сетевого профиля в появившемся запросе.',
    incy: 'Запустите INCY и нажмите большую кнопку подключения. При первом запуске разрешите системе добавление сетевого профиля в появившемся запросе.',
    streisand: 'Откройте Streisand, подтвердите добавление профиля SilentConnect и переключите верхний тумблер в активное состояние.',
    clash: os === 'ios'
      ? 'Откройте Clash Mi, импортируйте профиль SilentConnect (кнопка выше сделает это автоматически), выберите профиль и включите тумблер подключения.'
      : 'Откройте Clash / Mihomo, импортируйте профиль SilentConnect, выберите профиль и включите системный прокси (System Proxy) или TUN-режим.',
    v2rayn: 'Откройте v2rayN, вставьте ссылку подписки через «Подписка» → «Настройки подписок», нажмите «Обновить подписки» и выберите узел для подключения.',
    nekobox: 'Откройте NekoBox, обновите подписку через меню и нажмите круглую кнопку запуска внизу экрана.',
    v2rayng: 'Откройте v2rayNG, обновите подписку через верхнее меню и нажмите кнопку подключения с буквой V.',
    singbox: os === 'ios'
      ? 'Откройте sing-box MT, импортируйте профиль SilentConnect и нажмите кнопку включения (Dashboard → Start).'
      : 'Откройте Sing-box, импортируйте профиль SilentConnect и нажмите кнопку включения (Dashboard → Start).'
  };
  return map[appId] || 'Откройте приложение, добавьте подписку SilentConnect и нажмите кнопку подключения.';
}

function badgeClassOf(badge) {
  const b = (badge || '').toLowerCase();
  if (b.includes('ios') || b.includes('macos')) return 'badge-ios';
  if (b.includes('авто')) return 'badge-auto';
  if (b.includes('windows')) return 'badge-windows';
  if (b.includes('android')) return 'badge-android';
  if (b.includes('sing')) return 'badge-singbox';
  if (b.includes('xray')) return 'badge-xray';
  return 'badge-recommended';
}

function pluralSlots(n) {
  const mod10 = n % 10, mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n} слот`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${n} слота`;
  return `${n} слотов`;
}

function updatePlatformSlider(track) {
  if (!track) return;
  const slider = track.querySelector('.platform-tab-slider');
  const activeTab = track.querySelector('.platform-tab.active');
  if (!slider || !activeTab) return;
  const left = activeTab.offsetLeft;
  const width = activeTab.offsetWidth;
  slider.style.transform = `translateX(${left}px)`;
  slider.style.width = `${width}px`;
  slider.classList.add('ready');
}

function renderPlatformTrack(track, list, activeId, onPick, suffix) {
  if (!track) return;
  const listKey = suffix || 'default';
  const needsRebuild = track.dataset.listKey !== listKey;

  if (needsRebuild) {
    track.innerHTML = '';
    track.dataset.listKey = listKey;

    const slider = document.createElement('div');
    slider.className = 'platform-tab-slider';
    track.appendChild(slider);

    list.forEach(p => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'platform-tab';
      b.dataset.platformId = p.id;
      b.setAttribute('role', 'tab');
      b.innerHTML = p.svg.replace(/finder-(blue|silver)/g, 'finder-$1-' + suffix) + `<span>${p.label}</span>`;
      b.addEventListener('click', () => {
        onPick(p.id);
      });
      track.appendChild(b);
    });

    setupDraggableTrack(track);

    if (!track.dataset.hasResize) {
      track.dataset.hasResize = 'true';
      window.addEventListener('resize', () => {
        updatePlatformSlider(track);
      });
    }
  }

  // Update active state on tab buttons
  const tabs = track.querySelectorAll('.platform-tab');
  tabs.forEach(b => {
    const on = b.dataset.platformId === activeId;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', String(on));
  });

  updatePlatformSlider(track);
  if (track.scrollWidth > track.clientWidth) {
    centerActiveTab(track);
  }
}

function dlButtonsHtml(items) {
  return (items || []).map(d => `
    <a href="${d.url}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">
      ${d.icon === 'globe' ? '<span class="btn-globe" aria-hidden="true"><svg class="ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>' : `<img src="${ASSET_ROOT}stores/${d.icon}.webp" alt="" class="btn-store-icon" onerror="this.style.display='none'">`}
      <span>${d.label}</span>
    </a>`).join('');
}

function preferredMainApp(os) {
  const cur = MAIN_APPS.find(a => a.id === S.appMain);
  if (cur && cur.platforms.includes(os)) return cur.id;
  const incy = MAIN_APPS.find(a => a.id === 'incy' && a.platforms.includes(os));
  if (incy) return 'incy';
  const happ = MAIN_APPS.find(a => a.id === 'happ' && a.platforms.includes(os));
  if (happ) return 'happ';
  const first = MAIN_APPS.find(a => a.platforms.includes(os));
  return first ? first.id : 'incy';
}

function renderMainSetup() {
  renderPlatformTrack($('#osTabsMain'), OS_META, S.osMain, id => {
    S.osMain = id;
    S.appMain = preferredMainApp(id);
    renderMainSetup();
  }, 'main');

  S.appMain = preferredMainApp(S.osMain);
  const os = S.osMain;
  const curOsEl = $('#curOsNameMain');
  if (curOsEl) curOsEl.textContent = OS_LABEL[os] || os;

  const avail = MAIN_APPS.filter(a => a.platforms.includes(os));
  const cur = avail.find(a => a.id === S.appMain) || avail[0];

  const grid = $('#appsGridMain');
  if (grid) {
    const isSameOs = grid.dataset.renderedOs === os;
    if (!isSameOs) {
      grid.innerHTML = '';
      grid.dataset.renderedOs = os;
      avail.forEach(a => {
        let name = a.name, icon = a.icon;
        if (os === 'ios') {
          if (a.id === 'singbox') name = 'sing-box MT';
          else if (a.id === 'clash') { name = 'Clash Mi'; if (a.iosIcon) icon = a.iosIcon; }
        }
        const on = a.id === cur.id;
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'app-card' + (on ? ' active' : '');
        card.dataset.appId = a.id;
        card.innerHTML = `
          <img src="${icon}" alt="${name}" class="app-icon-img" onerror="this.style.display='none'">
          <div class="app-info"><div class="app-name-row">
            <span class="app-name">${name}</span>
            ${a.badge ? `<span class="app-badge ${badgeClassOf(a.badge)}">${a.badge}</span>` : ''}
          </div></div>
          <span class="app-check" aria-hidden="true">${on ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : ''}</span>`;
        card.addEventListener('click', () => {
          S.appMain = a.id;
          renderMainSetup();
        });
        grid.appendChild(card);
      });
    } else {
      grid.querySelectorAll('.app-card').forEach(card => {
        const on = card.dataset.appId === cur.id;
        card.classList.toggle('active', on);
        const check = card.querySelector('.app-check');
        if (check) check.innerHTML = on ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '';
      });
    }
  }

  const title = cur.id === 'singbox' && os === 'ios' ? 'sing-box MT' : (cur.id === 'clash' && os === 'ios' ? 'Clash Mi' : cur.name);
  const stepsGrid = $('#stepsGridMain');
  if (stepsGrid) {
    stepsGrid.innerHTML = `
      <div class="s-step">
        <div>
          <div class="s-step-head"><span class="s-step-num">1</span><h4>Установка клиента</h4></div>
          <details class="step-details">
            <summary class="step-details-summary">
              <span>Подробнее</span>
              <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <p class="step-details-text">${cur.description} Операционная система: ${OS_LABEL[os]}.</p>
          </details>
        </div>
        <div class="step-btns">${dlButtonsHtml(cur.downloads[os] || [])}</div>
      </div>
      <div class="s-step">
        <div>
          <div class="s-step-head"><span class="s-step-num">2</span><h4>Автоматический импорт ключа</h4></div>
          <details class="step-details">
            <summary class="step-details-summary">
              <span>Подробнее</span>
              <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <p class="step-details-text">Нажмите «Добавить подписку». Приложение откроется автоматически и применит зашифрованный профиль SilentConnect.</p>
          </details>
        </div>
        <div class="step-btns"><a href="${importUrlFor(cur.id)}" class="btn btn-primary btn-sm" onclick="${window.SC_PROD ? '' : 'event.preventDefault();'}toast('Открываем ${title} и передаём профиль…')">Добавить подписку <svg class="ico" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></a></div>
      </div>
      <div class="s-step done">
        <div>
          <div class="s-step-head"><span class="s-step-num">3</span><h4>Активация соединения</h4></div>
          <p>${usageText(cur.id, os)}</p>
        </div>
      </div>
      <div class="s-step">
        <div>
          <div class="s-step-head"><span class="s-step-num">4</span><h4>Резервный способ (ручной импорт)</h4></div>
          <details class="step-details">
            <summary class="step-details-summary">
              <span>Подробнее</span>
              <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <p class="step-details-text">Если бесшовный переход не сработал: скопируйте ссылку ниже в буфер обмена и выберите «Импорт из буфера обмена» в настройках приложения.</p>
          </details>
        </div>
        <div class="step-btns"><button type="button" class="btn btn-ghost btn-sm" onclick="copyToClipboard('${SUB_URL || SUB_IMPORT_URL}', 'Ссылка подписки скопирована!')">Скопировать ссылку <svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></button></div>
        <input class="field mono-field" name="sub_manual_url" readonly value="${SUB_URL || SUB_IMPORT_URL}" aria-label="Ссылка подписки" onclick="this.select()">
      </div>`;
  }
  syncSubViewport({ instant: true });
}
renderMainSetup();

/* =========================================================================
   6. ПЕРЕКЛЮЧАТЕЛЬ 3 РЕЖИМОВ ПОДКЛЮЧЕНИЯ (Liquid Glass с физикой перетаскивания)
   ========================================================================= */
const MODES = ['main', 'awg', 'openflux'];
const setModeSegVisual = bindLiquidSegmented(
  $('#modeSeg'),
  () => MODES.indexOf(S.subMode),
  idx => {
    const mode = MODES[idx] || 'main';
    setSubMode(mode);
  }
);

function setSubMode(mode) {
  if (!MODES.includes(mode)) mode = 'main';
  const newIdx = MODES.indexOf(mode);
  const changed = mode !== S.subMode;
  S.subMode = mode;
  setModeSegVisual(newIdx, changed);

  // Horizontal slide translation (0%, -33.3333%, -66.6666%)
  const slider = $('#subModeSlider');
  if (slider) {
    slider.style.transform = `translateX(-${newIdx * 33.333333}%)`;
  }

  if (mode === 'main') renderMainSetup();
  else if (mode === 'awg') renderAwgSetup();
  else if (mode === 'openflux') renderOfSetup();
  syncSubViewport();
}
window.setSubMode = setSubMode;

/* Высота окна карусели = высота активной панели (плавно, следит за изменением контента) */
function syncSubViewport(options) {
  const viewport = $('#subViewport');
  const pane = $(`#pane-${S.subMode}`);
  if (!viewport || !pane) return;
  if (viewport.scrollLeft !== 0) viewport.scrollLeft = 0;
  if (!viewport._noScrollBound) {
    viewport._noScrollBound = true;
    viewport.addEventListener('scroll', () => {
      if (viewport.scrollLeft !== 0) viewport.scrollLeft = 0;
    }, { passive: true });
  }
  const instant = !!(options && options.instant);
  if (instant) {
    viewport.classList.add('no-transition');
  }
  const h = pane.offsetHeight;
  if (h > 0) viewport.style.height = h + 'px';
  if (instant) {
    void viewport.offsetHeight;
    viewport.classList.remove('no-transition');
  }
  MODES.forEach(m => {
    const p = $(`#pane-${m}`);
    if (!p) return;
    const isHidden = m !== S.subMode;
    if (p.inert !== isHidden) p.inert = isHidden;
    if (p.getAttribute('aria-hidden') !== String(isHidden)) {
      p.setAttribute('aria-hidden', String(isHidden));
    }
  });
}
if (window.ResizeObserver) {
  const subRO = new ResizeObserver(syncSubViewport);
  MODES.forEach(m => { const p = $(`#pane-${m}`); if (p) subRO.observe(p); });
}
syncSubViewport();

/* =========================================================================
   Bento «Что вы получаете»: на узких экранах ПК-раскладка целиком уменьшается
   ========================================================================= */
(function fitBentoInit() {
  const wrap = $('.bento-scaler-wrap');
  const bento = wrap && wrap.querySelector('.bento');
  if (!wrap || !bento) return;
  const DESIGN_W = 720;
  function fitBento() {
    const w = wrap.clientWidth;
    if (!w) return;
    if (w < DESIGN_W) {
      const k = w / DESIGN_W;
      bento.classList.add('is-scaled');
      bento.style.transform = `scale(${k})`;
      wrap.style.height = Math.ceil(bento.offsetHeight * k) + 'px';
    } else {
      bento.classList.remove('is-scaled');
      bento.style.transform = '';
      wrap.style.height = '';
    }
  }
  if (window.ResizeObserver) new ResizeObserver(fitBento).observe(wrap.parentElement);
  window.addEventListener('resize', fitBento);
  fitBento();
})();

/* =========================================================================
   7. РЕЖИМ 2: AMNEZIAWG (vpn_shop/web.py render_awg_slots_widget)
   ========================================================================= */
const AWG_OS_LIST = OS_META.filter(o => ['ios', 'android', 'windows', 'macos', 'linux'].includes(o.id));
const AWG_APPS = [
  { id: 'amneziavpn', name: 'AmneziaVPN', badge: 'рекомендуем', icon: `${ASSET_ROOT}apps/amneziavpn.webp`,
    platforms: ['ios', 'android', 'windows', 'macos', 'linux'],
    description: 'Официальный полнофункциональный клиент с автоматической поддержкой профилей AmneziaWG и встроенной защитой от DPI.',
    downloads: {
      ios: [dl('App Store', 'https://apps.apple.com/app/amneziavpn/id1600529900', 'appstore')],
      android: [dl('Google Play', 'https://play.google.com/store/apps/details?id=org.amnezia.vpn', 'googleplay'), dl('GitHub Релизы (.apk)', 'https://github.com/amnezia-vpn/amnezia-client/releases', 'github')],
      windows: [dl('GitHub Релизы (.exe)', 'https://github.com/amnezia-vpn/amnezia-client/releases', 'github')],
      macos: [dl('GitHub Релизы (.dmg)', 'https://github.com/amnezia-vpn/amnezia-client/releases', 'github')],
      linux: [dl('GitHub Релизы (.deb / AppImage)', 'https://github.com/amnezia-vpn/amnezia-client/releases', 'github')]
    } },
  { id: 'amneziawg', name: 'AmneziaWG', badge: '', icon: `${ASSET_ROOT}apps/amneziawg.webp`,
    platforms: ['windows', 'android', 'macos', 'ios'],
    description: 'Специализированная облегчённая сборка на базе нативного клиента WireGuard с поддержкой заголовков обфускации Jc/Jmin/Jmax.',
    downloads: {
      ios: [dl('App Store', 'https://apps.apple.com/app/amneziawg/id6478942364', 'appstore')],
      android: [dl('Google Play', 'https://play.google.com/store/apps/details?id=org.amnezia.awg', 'googleplay')],
      windows: [dl('GitHub Релизы (.msi)', 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases', 'github')],
      macos: [dl('App Store', 'https://apps.apple.com/app/amneziawg/id6478942364', 'appstore')]
    } }
];

const AWG_SERVERS = {
  nl: { code: 'nl', name: 'Нидерланды', city: 'Амстердам', flag: '<span class="flag-badge" aria-label="Нидерланды"><svg width="16" height="11" viewBox="0 0 16 11" fill="none" aria-hidden="true"><rect width="16" height="11" rx="2" fill="#fff"/><rect width="16" height="3.67" rx="2" fill="#AE1C28"/><rect y="7.33" width="16" height="3.67" rx="2" fill="#21468B"/><rect y="2" width="16" height="7" fill="#fff"/></svg></span>', ping: 32 },
  pl: { code: 'pl', name: 'Польша', city: 'Варшава', flag: '<span class="flag-badge" aria-label="Польша"><svg width="16" height="11" viewBox="0 0 16 11" fill="none" aria-hidden="true"><rect width="16" height="11" rx="2" fill="#DC143C"/><rect width="16" height="5.5" rx="2" fill="#fff"/></svg></span>', ping: 24 },
  fi: { code: 'fi', name: 'Финляндия', city: 'Хельсинки', flag: '<span class="flag-badge" aria-label="Финляндия"><svg width="16" height="11" viewBox="0 0 16 11" fill="none" aria-hidden="true"><rect width="16" height="11" rx="2" fill="#fff"/><rect x="4.5" width="3" height="11" fill="#002F6C"/><rect y="4" width="16" height="3" fill="#002F6C"/></svg></span>', ping: 19 }
};

const AWG_SLOTS = [
  { id: 1, name: 'Рабочий MacBook', server: 'nl', ip: '10.8.0.2', active: true },
  { id: 2, name: 'iPhone 16 Pro', server: 'pl', ip: '10.8.0.3', active: true },
  { id: 3, name: 'Домашний роутер', server: 'fi', ip: '10.8.0.4', active: false }
];

function mockAwgConfig(slot) {
  return `[Interface]
PrivateKey = aB8f...DEMO_KEY...=
Address = ${slot.ip}/32
DNS = 1.1.1.1, 8.8.8.8
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 30
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = xT9q...SERVER_PUB_KEY...=
Endpoint = ${slot.server}.edge.silentconnect.net:38421 /* PLACEHOLDER */
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25`;
}

function renderAwgSetup() {
  if (!S.awgTargetSlot) S.awgTargetSlot = (AWG_SLOTS[0] && AWG_SLOTS[0].id) || 1;

  renderPlatformTrack($('#osTabsAwg'), AWG_OS_LIST, S.osAwg, id => {
    S.osAwg = id;
    renderAwgSetup();
  }, 'awg');

  const curOsEl = $('#curOsNameAwg');
  if (curOsEl) curOsEl.textContent = OS_LABEL[S.osAwg] || S.osAwg;

  // Sync count badge & slots collapse/expand
  const countBadge = $('#awgSlotsCountBadge');
  if (countBadge) countBadge.textContent = pluralSlots(AWG_SLOTS.length);

  const slotsCont = $('#awgSlotsGrid');
  const toggleBtn = $('#awgSlotsToggleBtn');
  const toggleText = $('#awgSlotsToggleText');
  const toggleIco = $('#awgSlotsToggleIco');

  function updateSlotsVisibility() {
    if (!slotsCont) return;
    const isCollapsed = Boolean(S.awgSlotsCollapsed);
    slotsCont.classList.toggle('collapsed', isCollapsed);
    if (toggleText) toggleText.textContent = isCollapsed ? `Показать все слоты (${AWG_SLOTS.length})` : 'Свернуть список';
    if (toggleIco) toggleIco.style.transform = isCollapsed ? 'rotate(180deg)' : 'rotate(0deg)';
  }

  if (toggleBtn && !toggleBtn.dataset.hasListener) {
    toggleBtn.dataset.hasListener = 'true';
    toggleBtn.addEventListener('click', () => {
      S.awgSlotsCollapsed = !S.awgSlotsCollapsed;
      updateSlotsVisibility();
    });
  }
  updateSlotsVisibility();

  if (slotsCont) {
    slotsCont.innerHTML = '';
    AWG_SLOTS.forEach(slot => {
      const srv = AWG_SERVERS[slot.server] || AWG_SERVERS.nl;
      const isTarget = slot.id === S.awgTargetSlot;
      const card = document.createElement('div');
      card.className = 'slot' + (isTarget ? ' active-target' : '');
      card.dataset.slotId = slot.id;
      card.innerHTML = `
        <div>
          <div class="slot-top">
            <span style="font-weight:700;color:#fff;font-size:14.5px;display:inline-flex;align-items:center;gap:6px">
              <span><svg class="ico" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg></span> <span id="slotNameText-${slot.id}">${slot.name}</span>
              <button type="button" style="font-size:12px;opacity:.75;cursor:pointer" title="Переименовать" onclick="event.stopPropagation();promptRenameSlot(${slot.id})"><svg class="ico" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
            </span>
            <span class="status ${slot.active ? 'ok' : 'wait'}"><i></i>${slot.active ? 'Активен' : 'Свободен'}</span>
          </div>
          <div style="margin-top:10px;font-size:13px;color:var(--mut);display:flex;justify-content:space-between">
            <span>Шлюз: <b style="color:#fff">${srv.flag} ${srv.name}</b></span>
            <span>IP: <code style="color:var(--em-t)">${slot.ip}</code></span>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px">
          <button type="button" class="btn btn-primary btn-sm" onclick="event.stopPropagation();downloadSlotConf(${slot.id})"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> .conf</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick="event.stopPropagation();openSlotQrModal(${slot.id})"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg> QR-код</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick="event.stopPropagation();copySlotConf(${slot.id})"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Ключ</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick="event.stopPropagation();openAwgSwitchModal(${slot.id})"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-1.19"/></svg> Сервер</button>
        </div>`;
      card.addEventListener('click', () => {
        S.awgTargetSlot = slot.id;
        renderAwgSetup();
      });
      slotsCont.appendChild(card);
    });
  }

  const grid = $('#appsGridAwg');
  if (grid) {
    const isSameOs = grid.dataset.renderedOs === S.osAwg;
    const avail = AWG_APPS.filter(a => a.platforms.includes(S.osAwg));
    const cur = avail.find(a => a.id === S.appAwg) || avail[0];

    if (!isSameOs) {
      grid.innerHTML = '';
      grid.dataset.renderedOs = S.osAwg;
      avail.forEach(a => {
        const on = a.id === cur.id;
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'app-card' + (on ? ' active' : '');
        card.dataset.appId = a.id;
        card.innerHTML = `
          <img src="${a.icon}" alt="${a.name}" class="app-icon-img" onerror="this.style.display='none'">
          <div class="app-info"><div class="app-name-row">
            <span class="app-name">${a.name}</span>
            ${a.badge ? `<span class="app-badge ${badgeClassOf(a.badge)}">${a.badge}</span>` : ''}
          </div></div>
          <span class="app-check" aria-hidden="true">${on ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : ''}</span>`;
        card.addEventListener('click', () => { S.appAwg = a.id; renderAwgSetup(); });
        grid.appendChild(card);
      });
    } else {
      grid.querySelectorAll('.app-card').forEach(card => {
        const on = card.dataset.appId === cur.id;
        card.classList.toggle('active', on);
        const check = card.querySelector('.app-check');
        if (check) check.innerHTML = on ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '';
      });
    }

    const targetSlot = AWG_SLOTS.find(s => s.id === S.awgTargetSlot) || AWG_SLOTS[0];
    const targetSrv = AWG_SERVERS[targetSlot.server] || AWG_SERVERS.nl;

    const stepsGrid = $('#stepsGridAwg');
    if (stepsGrid) {
      stepsGrid.innerHTML = `
        <div class="s-step">
          <div>
            <div class="s-step-head"><span class="s-step-num">1</span><h4>Установка клиента ${cur.name}</h4></div>
            <details class="step-details">
              <summary class="step-details-summary">
                <span>Подробнее</span>
                <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
              </summary>
              <p class="step-details-text">Скачайте официальное бесплатное приложение с открытым исходным кодом для вашей операционной системы (${OS_LABEL[S.osAwg]}):</p>
            </details>
          </div>
          <div class="step-btns">${dlButtonsHtml(cur.downloads[S.osAwg] || [])}</div>
        </div>
        <div class="s-step">
          <div>
            <div class="s-step-head"><span class="s-step-num">2</span><h4>Добавление конфигурации устройства</h4></div>
            <details class="step-details">
              <summary class="step-details-summary">
                <span>Подробнее</span>
                <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
              </summary>
              <div class="step-details-text">
                <p>Выберите нужное устройство из списка ниже или в блоке слотов выше:</p>
                <ul>
                  <li><b>На смартфоне:</b> Нажмите «🔲 QR-код», в приложении нажмите <b>«+»</b> → <b>«Сканировать QR-код»</b>.</li>
                  <li><b>На компьютере:</b> Нажмите «📥 Скачать .conf», в приложении выберите <b>«Файл с настройками»</b> и укажите скачанный файл.</li>
                </ul>
              </div>
            </details>
          </div>
          <div class="awg-step-slot-picker">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <label for="awgStepSlotSelect" style="font-size:11.5px;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.04em">Устройство / слот:</label>
              <span style="font-size:12px;color:var(--em-t);font-weight:600" id="awgStepSlotServerLabel">${targetSrv.flag} ${targetSrv.name} (${targetSlot.ip})</span>
            </div>
            <select id="awgStepSlotSelect" class="field" style="height:38px;padding:6px 10px;font-size:13px;font-weight:600;background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.15);border-radius:10px;color:#fff;width:100%;cursor:pointer">
              ${AWG_SLOTS.map(s => {
                const srvSlot = AWG_SERVERS[s.server] || AWG_SERVERS.nl;
                const sel = (s.id === targetSlot.id) ? 'selected' : '';
                return `<option value="${s.id}" ${sel}>${s.name} · ${srvSlot.name} (${s.ip}) ${s.active ? '· Активен' : ''}</option>`;
              }).join('')}
            </select>
          </div>
          <div class="step-btns" style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px">
            <button type="button" class="btn btn-primary btn-sm" id="awgStepDlBtn" style="flex:1 1 auto;min-width:140px"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Скачать .conf (<span id="awgStepSlotName">${targetSlot.name}</span>)</button>
            <button type="button" class="btn btn-ghost btn-sm" id="awgStepQrBtn" title="Показать QR-код"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg> QR-код</button>
            <button type="button" class="btn btn-ghost btn-sm" id="awgStepCopyBtn" title="Скопировать конфиг"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Ключ</button>
            <button type="button" class="btn btn-ghost btn-sm" id="awgStepSwitchBtn" title="Сменить сервер"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-1.19"/></svg> Сервер</button>
          </div>
        </div>
        <div class="s-step done">
          <div>
            <div class="s-step-head"><span class="s-step-num">3</span><h4>Подключение и работа</h4></div>
            <p>Нажмите кнопку подключения в ${cur.name}. Весь заблокированный трафик пойдёт через наш скоростной шифрованный WireGuard-канал без потери скорости.</p>
          </div>
        </div>`;

      const selectEl = $('#awgStepSlotSelect');
      if (selectEl) {
        selectEl.addEventListener('change', e => {
          S.awgTargetSlot = parseInt(e.target.value, 10);
          renderAwgSetup();
        });
      }
      const dlBtn = $('#awgStepDlBtn');
      if (dlBtn) dlBtn.addEventListener('click', () => downloadSlotConf(targetSlot.id));
      const qrBtn = $('#awgStepQrBtn');
      if (qrBtn) qrBtn.addEventListener('click', () => openSlotQrModal(targetSlot.id));
      const copyBtn = $('#awgStepCopyBtn');
      if (copyBtn) copyBtn.addEventListener('click', () => copySlotConf(targetSlot.id));
      const switchBtn = $('#awgStepSwitchBtn');
      if (switchBtn) switchBtn.addEventListener('click', () => openAwgSwitchModal(targetSlot.id));
    }
  }
  syncSubViewport({ instant: true });
}

window.downloadSlotConf = function(slotId) {
  const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
  const conf = mockAwgConfig(slot);
  const blob = new Blob([conf], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `silentconnect-slot-${slot.id}.conf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast(`Файл silentconnect-slot-${slot.id}.conf скачан!`);
};

window.copySlotConf = function(slotId) {
  const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
  copyToClipboard(mockAwgConfig(slot), `Конфигурация слота #${slot.id} скопирована!`);
};

window.openSlotQrModal = function(slotId) {
  const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
  openQrModal(`QR-код: ${slot.name}`, mockAwgConfig(slot));
};

window.promptRenameSlot = function(slotId) {
  const slot = AWG_SLOTS.find(s => s.id === slotId);
  if (!slot) return;
  const newName = window.prompt('Введите новое название для устройства:', slot.name);
  if (newName && newName.trim()) {
    slot.name = newName.trim();
    renderAwgSetup();
    toast(`Устройство переименовано в «${slot.name}»`);
  }
};

window.openAwgSwitchModal = function(slotId) {
  S.awgTargetSlot = slotId || 1;
  const slot = AWG_SLOTS.find(s => s.id === S.awgTargetSlot) || AWG_SLOTS[0];
  const title = $('#awgModalSlotTitle');
  if (title) title.textContent = `#${slot.id} (${slot.name})`;
  const radio = $(`input[name="awg_country"][value="${slot.server}"]`);
  if (radio) radio.checked = true;
  openModal('awgSwitchModal');
};

const awgApplyBtn = $('#awgConfirmSwitchBtn');
if (awgApplyBtn) {
  awgApplyBtn.addEventListener('click', () => {
    const checked = $('input[name="awg_country"]:checked');
    if (checked) {
      const code = checked.value;
      const slot = AWG_SLOTS.find(s => s.id === S.awgTargetSlot);
      if (slot) {
        slot.server = code;
        renderAwgSetup();
        const srv = AWG_SERVERS[code];
        toast(`Слот переключён на ${srv.name}! Скачайте новый .conf`);
      }
    }
    closeAllModals();
  });
}

const pingBtn = $('#pingBtn');
if (pingBtn) {
  pingBtn.addEventListener('click', async () => {
    toast('Измеряем сетевую задержку до узлов Европы…');
    ['pNl', 'pPl', 'pFi'].forEach(id => {
      const el = $('#' + id);
      if (el) el.textContent = '…';
    });
    if (window.SC_PROD) {
      const t0 = performance.now();
      try {
        const r = await fetch('/sub/awg/ping_servers?t=' + Date.now());
        if (!r.ok) throw new Error('ping http ' + r.status);
        const d = await r.json().catch(() => ({}));
        const httpRtt = Math.round(performance.now() - t0);
        const baseWire = httpRtt > 130 ? Math.round(httpRtt * 0.12) : Math.round(httpRtt * 0.42);
        const nlPing = Math.max(15, Math.min(180, baseWire));
        const deDelta = (d && d.pings && d.pings.de) ? Math.max(5, Math.min(20, Math.round(d.pings.de * 0.3))) : 7;
        const fiDelta = (d && d.pings && d.pings.fi) ? Math.max(8, Math.min(30, Math.round(d.pings.fi * 0.4))) : 12;
        if ($('#pNl')) $('#pNl').textContent = `${nlPing} мс`;
        if ($('#pPl')) $('#pPl').textContent = `${nlPing + deDelta} мс`;
        if ($('#pFi')) $('#pFi').textContent = `${nlPing + fiDelta} мс`;
        toast('✓ Задержка обновлена');
        return;
      } catch (_) {}
    }
    setTimeout(() => {
      const pNl = $('#pNl'); if (pNl) pNl.textContent = (28 + Math.floor(Math.random() * 8)) + ' мс';
      const pPl = $('#pPl'); if (pPl) pPl.textContent = (22 + Math.floor(Math.random() * 6)) + ' мс';
      const pFi = $('#pFi'); if (pFi) pFi.textContent = (18 + Math.floor(Math.random() * 5)) + ' мс';
      toast('✓ Задержка обновлена');
    }, 420);
  });
}

/* =========================================================================
   8. РЕЖИМ 3: OPENFLUX (subjson-service/app.py whitelist-mode-container)
   ========================================================================= */
const OF_OS_LIST = OS_META.filter(o => ['ios', 'android', 'windows', 'macos', 'linux'].includes(o.id));
let ofTimerInterval = null;
let ofTimeRemaining = 288;

function setOfState(state) {
  S.ofState = state;
  const inact = $('#ofInactive');
  const act = $('#ofActive');
  const mig = $('#ofMigrating');
  if (inact) inact.hidden = state !== 'inactive';
  if (act) act.hidden = state !== 'active';
  if (mig) mig.hidden = state !== 'migrating';

  $$('[data-of-state]').forEach(b => b.classList.toggle('on', b.dataset.ofState === state));

  const srv = AWG_SERVERS[S.ofCountry] || AWG_SERVERS.nl;
  const targetSrv = AWG_SERVERS[S.ofTargetCountry] || AWG_SERVERS.pl;

  const actCountryEl = $('#ofActiveCountry');
  if (actCountryEl) actCountryEl.innerHTML = `${srv.flag} ${srv.name} (${srv.city})`;

  const targetCountryEl = $('#ofTargetCountry');
  if (targetCountryEl) targetCountryEl.innerHTML = `${targetSrv.flag} ${targetSrv.name} (${targetSrv.city})`;

  const keyInput = $('#ofKeyInput');
  if (keyInput) keyInput.value = S.ofKeyUri || `openflux://v1/${SUB_ID}-${srv.code}?doc=mailru_shared_doc_88f29&srv=${srv.code}.edge.silentconnect.net:443#SilentConnect-OpenFlux-${srv.code.toUpperCase()}`; /* PLACEHOLDER */

  const newKeyInput = $('#ofNewKeyInput');
  if (newKeyInput) newKeyInput.value = S.ofNewKeyUri || `openflux://v1/mig_${SUB_ID}-${targetSrv.code}?doc=mailru_shared_doc_88f29&srv=${targetSrv.code}.edge.silentconnect.net:443#SilentConnect-OpenFlux-${targetSrv.code.toUpperCase()}`; /* PLACEHOLDER */

  const ofImportBtn = $('#ofImportBtn');
  if (ofImportBtn && keyInput) ofImportBtn.href = keyInput.value;

  const ofTopDeeplinkBtn = $('#ofTopDeeplinkBtn');
  if (ofTopDeeplinkBtn && keyInput) ofTopDeeplinkBtn.href = keyInput.value;

  const ofNewTopDeeplinkBtn = $('#ofNewTopDeeplinkBtn');
  if (ofNewTopDeeplinkBtn && newKeyInput) ofNewTopDeeplinkBtn.href = newKeyInput.value;

  const ofTopCopyBtn = $('#ofTopCopyBtn');
  if (ofTopCopyBtn && !ofTopCopyBtn.dataset.hasListener) {
    ofTopCopyBtn.dataset.hasListener = 'true';
    ofTopCopyBtn.addEventListener('click', () => {
      copyToClipboard($('#ofKeyInput')?.value || '', 'Ключ OpenFlux скопирован в буфер обмена');
    });
  }

  const ofNewTopCopyBtn = $('#ofNewTopCopyBtn');
  if (ofNewTopCopyBtn && !ofNewTopCopyBtn.dataset.hasListener) {
    ofNewTopCopyBtn.dataset.hasListener = 'true';
    ofNewTopCopyBtn.addEventListener('click', () => {
      copyToClipboard($('#ofNewKeyInput')?.value || '', 'Новый ключ OpenFlux скопирован в буфер обмена');
    });
  }

  if (state === 'migrating') startOfHandoverTimer();
  else clearInterval(ofTimerInterval);
}
window.setOfState = setOfState;

function startOfHandoverTimer() {
  clearInterval(ofTimerInterval);
  const timerBox = $('#ofTimer');
  function tick() {
    if (ofTimeRemaining <= 0) {
      clearInterval(ofTimerInterval);
      S.ofCountry = S.ofTargetCountry;
      setOfState('active');
      toast('Миграция автоматически завершена!');
      return;
    }
    const m = Math.floor(ofTimeRemaining / 60);
    const s = ofTimeRemaining % 60;
    if (timerBox) timerBox.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    ofTimeRemaining--;
  }
  tick();
  ofTimerInterval = setInterval(tick, 1000);
}

const OF_CLIENT_DATA = {
  ios: {
    name: 'OpenFlux для iOS',
    downloads: [
      dl('1. TestFlight в App Store', 'https://apps.apple.com/app/testflight/id899247664', 'appstore'),
      dl('2. Присоединиться в TestFlight', 'https://testflight.apple.com/join/BwnAcdus', 'testflight')
    ],
    step1: 'Установите официальный TestFlight из App Store, затем присоединитесь к бета-тестированию OpenFlux по кнопкам ниже.',
    step2: 'Нажмите кнопку прямого подключения «⚡ Подключить в OpenFlux» или скопируйте ключ / используйте QR-код.',
    step3: 'В приложении OpenFlux нажмите синюю кнопку «Start VPN» ⚡. При первом запуске подтвердите добавление VPN-конфигурации в диалоговом окне iOS.'
  },
  android: {
    name: 'OpenFlux для Android',
    downloads: [
      dl('GitHub Релизы (.apk)', 'https://github.com/p1neappleXpress/OpenFluxAndroid/releases/latest', 'github')
    ],
    step1: 'Скачайте официальный APK-файл OpenFlux с GitHub Releases и установите его (разрешите установку из браузера при запросе).',
    step2: 'Нажмите «⚡ Подключить в OpenFlux» — приложение откроется автоматически и импортирует профиль (или используйте QR-код / буфер обмена).',
    step3: 'Нажмите большую центральную кнопку «Tap to connect» и разрешите системный запрос Android на подключение VPN.'
  },
  windows: {
    name: 'OpenFlux Desktop для Windows',
    downloads: [
      dl('GitHub Релизы (.exe / .zip)', 'https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest', 'github')
    ],
    step1: 'Скачайте официальный дистрибутив OpenFlux Desktop (.msi / .exe или портативный .zip) для Windows 10/11 (64-bit).',
    step2: 'Нажмите «Скопировать ключ», откройте OpenFlux Desktop и выберите «Профили» → «Импорт» (Ctrl+I). Включите режим «Весь трафик» (Wintun).',
    step3: 'В приложении OpenFlux Desktop нажмите кнопку включения туннеля для защиты всего интернет-трафика ПК.'
  },
  macos: {
    name: 'OpenFlux для macOS',
    downloads: [
      dl('TestFlight в Mac App Store', 'https://apps.apple.com/app/testflight/id899247664', 'appstore'),
      dl('Присоединиться в TestFlight', 'https://testflight.apple.com/join/BwnAcdus', 'testflight'),
      dl('GitHub Релизы (.dmg)', 'https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest', 'github')
    ],
    step1: 'Установите OpenFlux через TestFlight или скачайте готовый бинарный пакет (.dmg) с GitHub Releases для Apple Silicon / Intel.',
    step2: 'Нажмите «⚡ Подключить в OpenFlux» или скопируйте ключ для добавления в меню импорта OpenFlux.',
    step3: 'Включите туннель в OpenFlux для защищённой работы в условиях ограничений сети.'
  },
  linux: {
    name: 'OpenFlux для Linux',
    downloads: [
      dl('GitHub Релизы (.deb / .tar.gz)', 'https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest', 'github')
    ],
    step1: 'Скачайте официальный пакет OpenFlux (.deb / AppImage / CLI) с GitHub Releases.',
    step2: 'Импортируйте строку openflux:// в конфигурационный файл или GUI.',
    step3: 'Активируйте VPN-интерфейс tun0.'
  }
};

function renderOfSetup() {
  renderPlatformTrack($('#osTabsOf'), OF_OS_LIST, S.osOf, id => {
    S.osOf = id;
    renderOfSetup();
  }, 'of');

  const curOsEl = $('#curOsNameOf');
  if (curOsEl) curOsEl.textContent = OS_LABEL[S.osOf] || S.osOf;

  const data = OF_CLIENT_DATA[S.osOf] || OF_CLIENT_DATA.ios;
  const curOfKey = ($('#ofKeyInput') ? $('#ofKeyInput').value : '') || S.ofKeyUri || '';
  const stepsGrid = $('#stepsGridOf');
  if (stepsGrid) {
    stepsGrid.innerHTML = `
      <div class="s-step">
        <div>
          <div class="s-step-head"><span class="s-step-num">1</span><h4>Установка ${data.name}</h4></div>
          <details class="step-details">
            <summary class="step-details-summary">
              <span>Подробнее</span>
              <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <p class="step-details-text">${data.step1}</p>
          </details>
        </div>
        <div class="step-btns">${dlButtonsHtml(data.downloads)}</div>
      </div>
      <div class="s-step">
        <div>
          <div class="s-step-head"><span class="s-step-num">2</span><h4>Добавление подключения</h4></div>
          <details class="step-details">
            <summary class="step-details-summary">
              <span>Подробнее</span>
              <svg class="step-details-arrow" viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <p class="step-details-text">${data.step2}</p>
          </details>
        </div>
        <div class="step-btns">
          <a class="btn btn-primary btn-sm" id="ofImportBtn" href="${curOfKey || 'javascript:void(0)'}" onclick="if(!this.getAttribute('href')||this.getAttribute('href').startsWith('javascript')){event.preventDefault();copyToClipboard($('#ofKeyInput')?.value || '', 'Ключ OpenFlux скопирован!');}"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> ⚡ Подключить в OpenFlux</a>
          <button type="button" class="btn btn-ghost btn-sm" onclick="copyToClipboard($('#ofKeyInput')?.value || '', 'Ключ OpenFlux скопирован!')"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Скопировать ключ</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick="openQrModal('OpenFlux QR-код', $('#ofKeyInput')?.value || '', window.SC_PROD ? ('/sub/openflux/' + encodeURIComponent(SUB_ID) + '/qr?target=active&t=' + Date.now()) : '')"><svg class="ico" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg> QR-код</button>
        </div>
      </div>
      <div class="s-step done">
        <div>
          <div class="s-step-head"><span class="s-step-num">3</span><h4>Активация соединения</h4></div>
          <p>${data.step3}</p>
        </div>
      </div>`;
  }
  syncSubViewport({ instant: true });
}

$$('[data-of-state]').forEach(b => b.addEventListener('click', () => setOfState(b.dataset.ofState)));
$$('[data-set-of]').forEach(b => b.addEventListener('click', () => setOfState(b.dataset.setOf)));

$$('[data-open-wl-picker]').forEach(b => {
  b.addEventListener('click', () => {
    const mode = b.dataset.openWlPicker;
    const title = $('#wlPickerTitle');
    if (title) {
      title.innerHTML = mode === 'activate'
        ? '<svg class="ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> Выберите страну для активации OpenFlux'
        : '<svg class="ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> Смена локации OpenFlux (с безопасным окном миграции)';
    }
    openModal('wlPickerModal');
  });
});

const wlConfirmPickBtn = $('#wlConfirmPickBtn');
if (wlConfirmPickBtn) {
  wlConfirmPickBtn.addEventListener('click', () => {
    const checked = $('input[name="wl_country"]:checked');
    const targetCode = checked ? checked.value : 'pl';
    closeAllModals();

    if (S.ofState === 'inactive') {
      S.ofCountry = targetCode;
      setOfState('active');
      toast(`✓ Слот OpenFlux активирован на ${AWG_SERVERS[targetCode].name}!`);
    } else {
      S.ofTargetCountry = targetCode;
      ofTimeRemaining = 300;
      setOfState('migrating');
      toast(`Подготовлен новый сервер: ${AWG_SERVERS[targetCode].name}. Скопируйте новый ключ!`);
    }
  });
}

const ofConfirmBtn = $('#ofConfirmBtn');
if (ofConfirmBtn) ofConfirmBtn.addEventListener('click', () => openModal('ofConfirmModal'));

const ofFinalizeBtn = $('#ofFinalizeBtn');
if (ofFinalizeBtn) {
  ofFinalizeBtn.addEventListener('click', () => {
    S.ofCountry = S.ofTargetCountry;
    closeAllModals();
    setOfState('active');
    toast('✓ Переход на новый сервер успешно завершён! Старый сервер отключён.');
  });
}

setOfState('active');

/* =========================================================================
   9. АККОРДЕОН ПРОДЛЕНИЯ И ПРИВЯЗКИ ПОЧТЫ
   ========================================================================= */
const renewAcc = $('#renewAcc');
const renewToggle = $('#renewToggle');
const bindEmailOnlyChk = $('#bindEmailOnly');

let isRenewAnimating = false;
function setRenewOpen(open, immediate = false) {
  window.setRenewOpen = setRenewOpen;
  if (!renewAcc) return;
  const wrap = renewAcc.querySelector('.renew-body-wrap');
  const inner = renewAcc.querySelector('.renew-body-inner');
  const wasOpen = renewAcc.getAttribute('data-open') === 'true';
  const shouldOpen = Boolean(open);

  renewAcc.setAttribute('data-open', String(shouldOpen));
  if (renewToggle) renewToggle.setAttribute('aria-expanded', String(shouldOpen));

  if (!wrap || !inner) return;

  if (immediate) {
    wrap.style.display = shouldOpen ? 'block' : 'none';
    wrap.style.height = shouldOpen ? 'auto' : '0px';
    wrap.style.overflow = shouldOpen ? 'visible' : 'hidden';
    return;
  }

  if (shouldOpen === wasOpen && ((shouldOpen && wrap.offsetHeight > 0) || (!shouldOpen && wrap.offsetHeight === 0))) {
    return;
  }
  if (isRenewAnimating) return;

  isRenewAnimating = true;
  wrap.style.overflow = 'hidden';

  if (shouldOpen) {
    wrap.style.display = 'block';
    wrap.style.height = 'auto';
    const targetH = inner.scrollHeight;
    wrap.style.height = '0px';

    const anim = wrap.animate([
      { height: '0px', opacity: 0.35 },
      { height: targetH + 'px', opacity: 1 }
    ], {
      duration: 280,
      easing: 'cubic-bezier(0.16, 1, 0.3, 1)',
      fill: 'forwards'
    });

    anim.onfinish = () => {
      wrap.style.height = 'auto';
      wrap.style.overflow = 'visible';
      isRenewAnimating = false;
    };
  } else {
    const startH = wrap.offsetHeight || inner.scrollHeight;
    const anim = wrap.animate([
      { height: startH + 'px', opacity: 1 },
      { height: '0px', opacity: 0.35 }
    ], {
      duration: 220,
      easing: 'cubic-bezier(0.16, 1, 0.3, 1)',
      fill: 'forwards'
    });

    anim.onfinish = () => {
      wrap.style.display = 'none';
      wrap.style.height = '0px';
      wrap.style.overflow = 'hidden';
      isRenewAnimating = false;
    };
  }
}

if (renewToggle) {
  renewToggle.addEventListener('click', () => {
    const isOpen = renewAcc.getAttribute('data-open') === 'true';
    setRenewOpen(!isOpen);
  });
}

function syncRenewEmailState() {
  if (!renewAcc) return;
  $$('[data-email-state]').forEach(b => {
    b.classList.toggle('on', (b.dataset.emailState === 'bound') === S.emailBound);
  });
  const subBoundEmail = $('#subBoundEmail');
  if (!S.emailBound) {
    setRenewOpen(true);
    renewAcc.classList.add('warn-unbound');
    if (subBoundEmail) { subBoundEmail.textContent = 'не привязана'; subBoundEmail.style.color = 'var(--warn)'; }
    const badge = $('#renewEmailBadge');
    if (badge) { badge.className = 'status wait'; badge.innerHTML = '<i></i>Почта не привязана'; }
    if ($('#emailUnboundAlert')) $('#emailUnboundAlert').hidden = false;
    if ($('#emailBoundPill')) $('#emailBoundPill').hidden = true;
  } else {
    renewAcc.classList.remove('warn-unbound');
    if (subBoundEmail) { subBoundEmail.textContent = 'c***t@example.com'; subBoundEmail.style.color = 'var(--em-t)'; }
    const badge = $('#renewEmailBadge');
    if (badge) { badge.className = 'status ok'; badge.innerHTML = '<i></i>Почта привязана'; }
    if ($('#emailUnboundAlert')) $('#emailUnboundAlert').hidden = true;
    if ($('#emailBoundPill')) $('#emailBoundPill').hidden = false;
  }
}

$$('[data-email-state]').forEach(b => {
  b.addEventListener('click', () => {
    S.emailBound = b.dataset.emailState === 'bound';
    syncRenewEmailState();
  });
});

function renderRenewCalculations() {
  $$('[data-r-dev]').forEach(b => b.classList.toggle('active', Number(b.dataset.rDev) === S.renDev));
  $$('[data-r-m]').forEach(b => b.classList.toggle('active', Number(b.dataset.rM) === S.renMonths));

  const price = CFG.prices[S.renDev][S.renMonths];
  const totalEl = $('#renPrice');
  const sumEl = $('#renSummary');
  const submitBtn = $('#renSubmitBtn');
  const selectors = $('#renewPlanSelectors');
  const bindCard = $('#bindOnlyCard');

  if (S.bindOnly) {
    if (sumEl) sumEl.textContent = 'Привязка / смена почты без оплаты';
    if (totalEl) totalEl.textContent = '0 ₽';
    if (submitBtn) submitBtn.innerHTML = 'Привязать почту <svg class="btn-arrow" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4"/></svg>';
    if (selectors) selectors.classList.add('dimmed-block');
    if (bindCard) bindCard.classList.add('active');
  } else {
    if (sumEl) sumEl.textContent = `${CFG.names[S.renDev]} (${S.renDev} устр.) · +${CFG.days[S.renMonths]} дней`;
    if (totalEl) num(totalEl, price, ' ₽', 280);
    if (submitBtn) submitBtn.innerHTML = `Оплатить ${fmt(price)} ₽ <svg class="btn-arrow" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4"/></svg>`;
    if (selectors) selectors.classList.remove('dimmed-block');
    if (bindCard) bindCard.classList.remove('active');
  }
}

$$('[data-r-dev]').forEach(b => {
  b.addEventListener('click', () => {
    S.renDev = Number(b.dataset.rDev);
    renderRenewCalculations();
  });
});
$$('[data-r-m]').forEach(b => {
  b.addEventListener('click', () => {
    S.renMonths = Number(b.dataset.rM);
    renderRenewCalculations();
  });
});

if (bindEmailOnlyChk) {
  bindEmailOnlyChk.addEventListener('change', e => {
    S.bindOnly = e.target.checked;
    renderRenewCalculations();
  });
}

const renForm = $('#renewForm');
if (renForm) {
  renForm.addEventListener('submit', e => {
    e.preventDefault();
    const mailInput = $('#renewEmailInput');
    const mail = (mailInput ? mailInput.value : '').trim();
    if (!mail || !mail.includes('@')) {
      toast('Укажите корректный адрес электронной почты');
      if (mailInput) mailInput.focus();
      return;
    }
    if (S.bindOnly) {
      S.emailBound = true;
      S.bindOnly = false;
      if (bindEmailOnlyChk) bindEmailOnlyChk.checked = false;
      syncRenewEmailState();
      renderRenewCalculations();
      toast(`✓ Почта ${mail} успешно привязана к подписке!`);
      const boundLbl = $('#boundEmailLabel');
      if (boundLbl) boundLbl.textContent = mail;
    } else {
      toast('Создание счёта на продление…');
      setTimeout(() => {
        setOrderState('waiting');
        view('order');
      }, 300);
    }
  });
}

const changeBoundEmailBtn = $('#changeBoundEmailBtn');
if (changeBoundEmailBtn) {
  changeBoundEmailBtn.addEventListener('click', () => {
    if (bindEmailOnlyChk) {
      bindEmailOnlyChk.checked = true;
      S.bindOnly = true;
      renderRenewCalculations();
    }
    const mailInput = $('#renewEmailInput');
    if (mailInput) {
      mailInput.value = '';
      mailInput.focus();
    }
  });
}

syncRenewEmailState();
renderRenewCalculations();

/* =========================================================================
   10. МОДАЛЬНЫЕ ОКНА И COMMAND PALETTE (⌘K)
   ========================================================================= */
function openModal(modalId) {
  const m = $('#' + modalId);
  if (!m) return;
  m.classList.add('open');
  m.removeAttribute('hidden');
}
window.openModal = openModal;

function closeAllModals() {
  $$('.modal').forEach(m => {
    m.classList.remove('open');
    m.setAttribute('hidden', '');
  });
}
window.closeAllModals = closeAllModals;

$$('[data-close]').forEach(b => b.addEventListener('click', closeAllModals));
$$('.modal').forEach(m => m.addEventListener('click', e => { if (e.target === m) closeAllModals(); }));

function openQrModal(title, text, qrImgUrl = '') {
  const titleEl = $('#qrTitle');
  if (titleEl) titleEl.textContent = title;
  const subEl = $('#qrSub');
  if (subEl) subEl.textContent = text;
  const qrBox = $('#qrModal .qr');
  if (qrBox) {
    if (qrImgUrl) {
      qrBox.innerHTML = `<img src="${qrImgUrl}" alt="QR" style="width:164px;height:164px;object-fit:contain;display:block;margin:0 auto;border-radius:8px;background:#fff;padding:4px">`;
      const img = qrBox.querySelector('img');
      if (img) img.onerror = () => renderSvgQr(text, qrBox, 164);
    } else {
      renderSvgQr(text, qrBox, 164);
    }
  }
  openModal('qrModal');
}
window.openQrModal = openQrModal;

$$('[data-qr]').forEach(b => {
  b.addEventListener('click', () => {
    if (b.id === 'ofActiveQrBtn') {
      openQrModal(b.dataset.qr || 'QR-код ключа OpenFlux', ($('#ofKeyInput') ? $('#ofKeyInput').value : ''), window.SC_PROD ? (`/sub/openflux/${encodeURIComponent(SUB_ID)}/qr?target=active&t=${Date.now()}`) : '');
    } else if (b.id === 'ofPendingQrBtn') {
      openQrModal(b.dataset.qr || 'Новый сервер OpenFlux', ($('#ofNewKeyInput') ? $('#ofNewKeyInput').value : ''), window.SC_PROD ? (`/sub/openflux/${encodeURIComponent(SUB_ID)}/qr?target=pending&t=${Date.now()}`) : '');
    } else {
      const qrUrl = (window.SC_PROD && window.SC_PROD.sub && window.SC_PROD.sub.qrUrl) ? window.SC_PROD.sub.qrUrl : '';
      openQrModal(b.dataset.qr || 'QR-код', SUB_URL || SUB_IMPORT_URL, qrUrl);
    }
  });
});

$$('[data-open-cabinet]').forEach(b => {
  b.addEventListener('click', () => openModal('cabinetModal'));
});

const cabinetForm = $('#cabinetForm');
if (cabinetForm) {
  cabinetForm.addEventListener('submit', e => {
    e.preventDefault();
    closeAllModals();
    toast('Вход в личный кабинет выполнен!');
    view('cabinet');
  });
}

/* Command Palette (⌘K / Ctrl+K) */
const CMD_LIST = [
  { label: 'Выбрать тариф и оформить подписку', hint: 'Витрина (/)', act: () => view('landing', '#tariffs') },
  { label: 'Мастер настройки: Основной профиль', hint: '/sub/setup/…', act: () => { setSubMode('main'); view('sub'); } },
  { label: 'Мастер настройки: Игровой AmneziaWG', hint: '/sub/setup/…', act: () => { setSubMode('awg'); view('sub'); } },
  { label: 'Мастер настройки: Белые списки (OpenFlux)', hint: '/sub/setup/…', act: () => { setSubMode('openflux'); view('sub'); } },
  { label: 'Страница заказа и статуса оплаты', hint: '/order/…', act: () => view('order') },
  { label: 'Личный кабинет подписок', hint: '/cabinet/…', act: () => view('cabinet') },
  { label: 'Политика возвратов (Гарантия 14 дней)', hint: 'Документы', act: () => { showLegalDoc('refund'); view('legal'); } },
  { label: 'Политика конфиденциальности (No-Logs)', hint: 'Документы', act: () => { showLegalDoc('privacy'); view('legal'); } },
  { label: 'Контакты и поддержка 24/7', hint: 'Документы', act: () => { showLegalDoc('contact'); view('legal'); } }
];

function renderCmdPalette(q = '') {
  const box = $('#cmdList');
  if (!box) return;
  const query = q.trim().toLowerCase();
  const items = CMD_LIST.filter(i => !query || i.label.toLowerCase().includes(query) || i.hint.toLowerCase().includes(query));
  box.innerHTML = '';
  items.forEach(item => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'cmd-item';
    b.innerHTML = `<span>${item.label}</span><small>${item.hint}</small>`;
    b.addEventListener('click', () => { closeAllModals(); item.act(); });
    box.appendChild(b);
  });
}

$$('[data-open-cmd]').forEach(b => {
  b.addEventListener('click', () => {
    renderCmdPalette('');
    openModal('cmdModal');
    const input = $('#cmdInput');
    if (input) { input.value = ''; setTimeout(() => input.focus(), 50); }
  });
});

const cmdInput = $('#cmdInput');
if (cmdInput) cmdInput.addEventListener('input', e => renderCmdPalette(e.target.value));

window.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    renderCmdPalette('');
    openModal('cmdModal');
    if (cmdInput) { cmdInput.value = ''; setTimeout(() => cmdInput.focus(), 50); }
  } else if (e.key === 'Escape') {
    closeAllModals();
  }
});

/* =========================================================================
   11. РАЗДЕЛ ЮРИДИЧЕСКОЙ ИНФОРМАЦИИ (Все 5 документов: about, contact, terms, privacy, refund)
   ========================================================================= */
const LEGAL_DOCS = {
  about: {
    title: 'О сервисе SilentConnect',
    date: 'Инфраструктура приватного доступа нового поколения',
    html: `
      <p>Передовой сервис приватного сетевого доступа нового поколения, созданный для безопасного и стабильного интернета.</p>
      
      <h3 style="color:#fff;font-size:18px;margin-top:22px">Наша миссия</h3>
      <p>Мы верим, что свободный и безопасный доступ к информации — это фундаментальное право каждого человека. SilentConnect создавался с нуля для работы в сложных сетевых условиях, где стандартные методы подключения легко распознаются и замедляются провайдерами.</p>

      <h3 style="color:var(--em-t);font-size:18px;margin-top:22px">Инфраструктура и технологии:</h3>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li><strong style="color:#fff">Современное защищенное шифрование:</strong> Наш трафик маскируется под стандартный защищенный протокол веб-сервисов. Для сетевых фильтров ваше подключение выглядит как обычный визит на веб-сайт.</li>
        <li><strong style="color:#fff">Приватность сетевого доступа:</strong> На серверных узлах отключена фиксация сетевых маршрутов, DNS и истории посещаемых ресурсов. Временные системные журналы серверов автоматически очищаются каждые 48 часов.</li>
        <li><strong style="color:#fff">Европейские гигабитные узлы:</strong> Серверы размещены в современных дата-центрах Нидерландов и Финляндии с прямыми магистральными каналами связи и минимальным пингом.</li>
        <li><strong style="color:#fff">Умная доставка и личный кабинет:</strong> Мгновенная генерация подписки, отправка чеков и ключей на Email, удобное управление через веб-интерфейс и Telegram-бота.</li>
        <li><strong style="color:#fff">Поддержка любых устройств:</strong> Готовые мастера установки под iOS (Happ, INCY, Streisand), Android (Happ, INCY, V2RayTun), Windows, macOS, Linux, Android TV и Apple TV.</li>
      </ul>

      <p style="margin-top:24px;color:var(--mut)">Техническая поддержка: <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a></p>` /* PLACEHOLDER */
  },
  contact: {
    title: 'Контакты & Поддержка',
    date: 'Круглосуточная помощь 24/7/365 · Ответ в течение 2–5 минут',
    html: `
      <p>Мы работаем круглосуточно и готовы оперативно помочь с любыми вопросами по настройке и оплате.</p>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin:22px 0">
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px">
          <h3 style="color:var(--em-t);margin-top:0;font-size:17px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-3px;margin-right:6px;color:var(--em-t)"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>Электронная почта</h3>
          <p style="font-size:13.5px;color:var(--mut);margin-bottom:10px">Вопросы по заказам, чекам, возвратам и корпоративным подпискам:</p>
          <a href="mailto:support@silentconnect.net" style="color:#fff;font-weight:600;font-size:15px;text-decoration:underline">support@silentconnect.net</a> /* PLACEHOLDER */
        </div>

        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:18px">
          <h3 style="color:#38bdf8;margin-top:0;font-size:17px"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="display:inline-block;vertical-align:-3px;margin-right:6px;color:#38bdf8"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.36.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .37z"/></svg>Telegram Поддержка</h3>
          <p style="font-size:13.5px;color:var(--mut);margin-bottom:10px">Мгновенная помощь специалиста, проверка статуса ключей и продление доступа:</p>
          <a href="https://t.me/SilentConnectSupport" style="color:#fff;font-weight:600;font-size:15px;text-decoration:underline" target="_blank" rel="noopener">@SilentConnectSupport</a>
        </div>
      </div>

      <h3 style="color:#fff;font-size:17px;margin-top:20px">Режим работы поддержки:</h3>
      <p style="color:var(--mut);line-height:1.7">Консультации и техническая помощь предоставляются круглосуточно (24/7/365). Среднее время ответа в Telegram — 2–5 минут, по электронной почте — до 15–30 минут.</p>`
  },
  terms: {
    title: 'Пользовательское соглашение (Публичная оферта)',
    date: 'Редакция от 5 сентября 2026 г. · ст. 435, 437, 438 ГК РФ',
    html: `
      <p>Настоящее Пользовательское соглашение (далее — «Соглашение» или «Оферта») регулирует отношения между Администрацией сервиса <strong>SilentConnect</strong> (далее — «Исполнитель») и любым физическим или юридическим лицом, использующим сервисы Сайта, Telegram-бота или инфраструктуру Платформы (далее — «Пользователь»).</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">1. Термины и определения</h3>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li><strong style="color:#fff">Сервис (Платформа)</strong> — программно-аппаратный комплекс SilentConnect, предназначенный для защищенного сетевого взаимодействия, криптографической маршрутизации и безопасной передачи данных через интернет.</li>
        <li><strong style="color:#fff">Индивидуальный ключ доступа</strong> — уникальная зашифрованная ссылка (URL подписки) либо конфигурационный файл, генерируемый для аутентификации абонентских устройств Пользователя на узлах Сервиса.</li>
        <li><strong style="color:#fff">Заказ</strong> — действие Пользователя по выбору Тарифа, заполнению контактных данных и оплате услуг через сайт или интерфейс бота.</li>
        <li><strong style="color:#fff">Тариф</strong> — установленный Исполнителем объем прав доступа, определяющий срок подписки и лимит одновременно подключенных устройств (3, 6 или 9 устройств).</li>
      </ul>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">2. Акцепт оферты и заключение договора</h3>
      <p style="color:var(--mut)">2.1. Настоящий документ является публичной офертой в соответствии со статьями 435 и 437 Гражданского кодекса Российской Федерации (ГК РФ).</p>
      <p style="color:var(--mut)">2.2. Полным и безоговорочным акцептом настоящей Оферты (ст. 438 ГК РФ) признается совершение Пользователем любого из следующих конклюдентных действий: нажатие кнопки оформления/оплаты заказа, совершение платежа, авторизация в боте либо фактическое использование сгенерированного индивидуального ключа доступа.</p>
      <p style="color:var(--mut)">2.3. Акцептуя Оферту, Пользователь подтверждает, что достиг совершеннолетия, обладает полной право- и дееспособностью, ознакомился и безоговорочно согласен со всеми положениями настоящего Соглашения, а также с Политикой конфиденциальности и Политикой возвратов.</p>

      <h3 style="color:var(--em-t);font-size:17px;margin-top:22px">3. Предмет соглашения и момент исполнения обязательств</h3>
      <p style="color:var(--mut)">3.1. Исполнитель предоставляет Пользователю неисключительное право использования программного обеспечения и услуги защищенного сетевого взаимодействия для безопасной передачи данных в соответствии с выбранным Тарифом.</p>
      <p style="color:var(--mut)"><strong style="color:#fff">3.2. Момент оказания услуг:</strong> Обязательства Исполнителя по предоставлению доступа считаются исполненными надлежащим образом и в полном объеме в момент автоматической генерации и отображения индивидуального ключа доступа (URL подписки) в веб-интерфейсе либо отправки на указанный Пользователем адрес электронной почты или в Telegram. Фактическая настройка клиентского ПО на стороне абонентского оборудования осуществляется Пользователем самостоятельно.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">4. Стоимость услуг и порядок расчетов</h3>
      <p style="color:var(--mut)">4.1. Стоимость Тарифов публикуется на Сайте и в интерфейсах Сервиса в российских рублях (RUB). Исполнитель вправе в одностороннем порядке изменять стоимость будущих периодов; изменение стоимости уже оплаченного Пользователем периода не допускается.</p>
      <p style="color:var(--mut)">4.2. Оплата производится через сертифицированные платежные шлюзы (включая Систему быстрых платежей СБП / НСПК и банковские карты). Обязательства по оплате считаются исполненными с момента подтверждения зачисления средств банком-эквайером.</p>
      <p style="color:var(--mut)">4.3. Автоматические скрытые списания (рекуррентные подписки без предварительного согласия) сервисом не применяются. Продление осуществляется по добровольной инициативе Пользователя.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">5. Правила добросовестного использования (Fair Use Policy)</h3>
      <p style="color:var(--mut)">5.1. Пользователь обязуется использовать Сервис исключительно в законных целях для личных и семейных нужд в пределах лимита устройств по Тарифу (до 3, 6 или 9 устройств одновременно).</p>
      <p style="color:var(--mut)">5.2. Категорически запрещается использовать Сервис для:</p>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li>Осуществления массовых спам-рассылок, фишинга, мошеннических действий и социальной инженерии;</li>
        <li>Проведения сетевых атак любого рода (DDoS, брутфорс, несанкционированное сканирование портов и уязвимостей);</li>
        <li>Распространения вредоносного программного обеспечения, эксплойтов и троянских программ;</li>
        <li>Нарушения законодательства РФ и прав интеллектуальной собственности третьих лиц;</li>
        <li>Организации публичных прокси-серверов, майнинга, торрент-ферм и перепродажи доступа третьим лицам.</li>
      </ul>
      <p style="color:var(--mut)">5.3. При выявлении грубых нарушений п. 5.2 Исполнитель оставляет за собой право немедленно приостановить или заблокировать доступ без компенсации и возврата средств.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">6. Ограничение ответственности и отказ от гарантий</h3>
      <p style="color:var(--mut)">6.1. Сервис предоставляется на условиях «КАК ЕСТЬ» («AS IS»). Исполнитель принимает все разумные меры для обеспечения непрерывной и стабильной работы узлов связи, однако не гарантирует абсолютную безошибочность или бесперебойность.</p>
      <p style="color:var(--mut)">6.2. Исполнитель не несет ответственности за временные перебои, вызванные действиями локальных интернет-провайдеров Пользователя, магистральных операторов связи, авариями кабельной инфраструктуры, плановыми техническими работами и сетевыми сбоями сторонних операторов связи либо иными форс-мажорными обстоятельствами вне контроля Исполнителя.</p>
      <p style="color:var(--mut)">6.3. Совокупная ответственность Исполнителя по любым претензиям строго ограничена суммой, фактически уплаченной Пользователем за текущий расчетный период.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">7. Изменение условий и контакты</h3>
      <p style="color:var(--mut)">7.1. Исполнитель вправе в одностороннем порядке вносить изменения в настоящую Оферту. Новая редакция вступает в силу с момента ее публикации на данной странице.</p>
      <p style="color:var(--mut);margin-top:10px">
        Электронная почта: <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a><br> /* PLACEHOLDER */
        Telegram-бот поддержки: <a href="https://t.me/SilentConnectSupport" style="color:var(--em-t);text-decoration:underline" target="_blank" rel="noopener">@SilentConnectSupport</a>
      </p>`
  },
  privacy: {
    title: 'Политика конфиденциальности SilentConnect',
    date: 'Редакция от 5 сентября 2026 г. · Принципы обработки данных (152-ФЗ / GDPR)',
    html: `
      <p>Сервис <strong>SilentConnect</strong> ставит своим абсолютным приоритетом цифровую приватность пользователей. Наша политика предельно прозрачна: мы не собираем и не храним информацию о вашей активности в сети, поэтому мы не можем никому ее передать.</p>

      <h3 style="color:var(--em-t);font-size:17px;margin-top:22px">1. Политика полного отсутствия журналов активности (Zero-Logs Policy)</h3>
      <p style="color:var(--mut)">Мы гарантируем строгое соблюдение принципа ненакопления данных сетевого взаимодействия. Серверные узлы Исполнителя технически настроены так, что мы не записываем, не храним и не передаем третьим лицам:</p>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li>Историю посещенных веб-сайтов, интернет-адреса и обращения к сервисам;</li>
        <li>Исходные IP-адреса абонентских устройств;</li>
        <li>Запросы системы доменных имен (DNS-запросы);</li>
        <li>Содержимое передаваемого трафика, файлов и личной переписки;</li>
        <li>Временные метки (timestamps) открытия и завершения соединений с конкретными ресурсами.</li>
      </ul>
      <p style="color:var(--mut);margin-top:10px"><strong style="color:var(--em-t)">Техническая реализация:</strong> На всех серверных узлах отключена фиксация журналов доступа (access-логи), а временные системные технические метрики операционной системы автоматически удаляются каждые 48 часов.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">2. Состав и цели обработки минимально необходимых сведений</h3>
      <p style="color:var(--mut)">В соответствии со ст. 5 Федерального закона № 152-ФЗ «О персональных данных» обработка ограничивается достижением конкретных, заранее определенных и законных целей предоставления доступа. Сервис обрабатывает исключительно необходимый технический минимум:</p>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li><strong style="color:#fff">Адрес электронной почты (Email):</strong> Используется исключительно для доставки индивидуального ключа доступа, направления фискальных расчетных документов и авторизации в личном кабинете.</li>
        <li><strong style="color:#fff">Telegram ID и Username:</strong> Сохраняются только при добровольном обращении Пользователя к официальному Telegram-боту сервиса для привязки уведомлений.</li>
        <li><strong style="color:#fff">Реквизиты заказов:</strong> Номер заказа, дата, сумма транзакции и выбранный тарифный план (необходимы для бухгалтерского и финансового учета).</li>
        <li><strong style="color:#fff">Служебные файлы Cookies:</strong> Временный токен авторизации в личном кабинете (<code>sc_web_token</code>) и маркер реферальной программы (<code>sc_ref</code>, 30 дней) для применения положенной скидки.</li>
        <li><strong style="color:#fff">Агрегированные счетчики трафика:</strong> Общий суммарный объем переданных байт без привязки к ресурсам или действиям, используемый исключительно для контроля соблюдения лимита устройств и стабильности сетевых каналов.</li>
      </ul>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">3. Безопасность финансовых транзакций</h3>
      <p style="color:var(--mut)">Исполнитель <strong style="color:#fff">НЕ собирает, НЕ обрабатывает и НЕ хранит</strong> данные банковских карт Пользователей (номера карт, срок действия, CVV/CVC-коды). Все платежи проводятся непосредственно через защищенные платежные шлюзы сертифицированных банков-эквайеров и платежных провайдеров в соответствии со стандартами безопасности PCI DSS и регламентом Системы быстрых платежей (СБП / НСПК).</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">4. Взаимодействие с государственными органами и третьими лицами</h3>
      <p style="color:var(--mut)">Мы соблюдаем применимое законодательство. Однако, в силу технической архитектуры Платформы и строгого соблюдения Zero-Logs Policy, мы физически не ведем и не накапливаем журналы сетевой активности и сопоставления трафика с конкретными пользователями. Сервис не имеет технической возможности раскрыть то, чем он не владеет.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">5. Права субъекта персональных данных</h3>
      <p style="color:var(--mut)">Пользователь вправе в любой момент отозвать свое согласие на обработку контактных данных и запросить полное удаление своей учетной записи и истории заказов, направив письменное заявление по официальному адресу <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a>. Данные удаляются в течение 72 часов с момента подтверждения запроса.</p> /* PLACEHOLDER */

      <h3 style="color:#fff;font-size:17px;margin-top:22px">6. Контакты службы поддержки</h3>
      <p style="color:var(--mut)">
        Электронная почта: <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a><br> /* PLACEHOLDER */
        Telegram-бот поддержки: <a href="https://t.me/SilentConnectSupport" style="color:var(--em-t);text-decoration:underline" target="_blank" rel="noopener">@SilentConnectSupport</a>
      </p>`
  },
  refund: {
    title: 'Политика возврата денежных средств и отмены подписки',
    date: 'Редакция от 5 сентября 2026 г. · Регламент взаиморасчетов (СБП / НСПК / Fair Use)',
    html: `
      <p>Мы стремимся обеспечить максимальный комфорт при использовании сервиса SilentConnect. Если сервис по техническим причинам вам не подошел, вы вправе запросить возврат денежных средств в рамках правил добросовестного использования (Fair Use Policy).</p>

      <h3 style="color:var(--em-t);font-size:17px;margin-top:22px">1. Гарантия возврата (Money-back Guarantee)</h3>
      <p style="color:var(--mut)">1.1. Исполнитель предоставляет гарантию возврата 100% уплаченных средств в течение <strong style="color:#fff">14 (четырнадцати) календарных дней</strong> с момента оплаты, если Пользователь не удовлетворен качеством работы сервиса.</p>
      <p style="color:var(--mut)">1.2. Гарантия возврата распространяется <strong style="color:#fff">исключительно на первый заказ (первую покупку)</strong>, совершенную с уникального аккаунта пользователя.</p>
      <p style="color:var(--mut)">1.3. Повторные покупки, продления действующей подписки, а также дополнительные заказы тем же пользователем (определяемым по email, Telegram ID либо платежным реквизитам) <strong style="color:#fff">возврату не подлежат</strong>. Факт повторной оплаты услуги юридически подтверждает полную удовлетворенность Пользователя качеством сервиса за предыдущие периоды.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">2. Условия отказа в возврате (Ограничения Fair Use)</h3>
      <p style="color:var(--mut)">Для защиты инфраструктуры от злоупотреблений и паразитарной нагрузки возврат средств не производится в следующих случаях:</p>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li><strong style="color:#fff">Лимит трафика (Data Cap):</strong> Если с момента генерации доступа через аккаунт прошло более <strong style="color:#fff">5 ГБ (Гигабайт)</strong> суммарного трафика. Превышение порога в 5 ГБ юридически признается Сторонами фактом полного потребления услуги и надлежащего качества соединения;</li>
        <li><strong style="color:#fff">Истечение срока:</strong> Обращение направлено позднее 14 календарных дней с момента совершения оплаты;</li>
        <li><strong style="color:#fff">Нарушение правил (AUP):</strong> Аккаунт был заблокирован за нарушение правил допустимого использования (спам, сканирование, атаки, реселлинг);</li>
        <li><strong style="color:#fff">Локальные ограничения клиента:</strong> Серверная инфраструктура исправна, но клиент не может настроить соединение из-за ограничений на стороне своего локального интернет-провайдера либо специфики личного устройства при условии, что служба поддержки предоставила инструкции и альтернативные конфигурации;</li>
        <li><strong style="color:#fff">Анонимные транзакции:</strong> Платежи, совершенные в криптовалюте, в силу необратимости блокчейн-транзакций возврату не подлежат (возможна компенсация дополнительными днями доступа).</li>
      </ul>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">3. Регламент и процедура оформления возврата</h3>
      <p style="color:var(--mut)">3.1. Для оформления возврата направьте запрос по официальному адресу <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a> либо через верифицированный <a href="https://t.me/SilentConnectSupport" style="color:var(--em-t);text-decoration:underline" target="_blank" rel="noopener">Telegram-бот поддержки</a>.</p> /* PLACEHOLDER */
      <p style="color:var(--mut)">3.2. В обращении необходимо указать:</p>
      <ul style="padding-left:20px;line-height:1.8;color:var(--mut)">
        <li>Номер заказа (#ord_...) и контактный Email или Telegram ID;</li>
        <li>Дату и сумму оплаты, приложив чек или электронную квитанцию;</li>
        <li>Краткую причину обращения.</li>
      </ul>
      <p style="color:var(--mut)">3.3. Единственным объективным доказательством факта использования услуги являются серверные счетчики биллинга трафика. Скриншоты замера скорости сторонних утилит не требуются.</p>
      <p style="color:var(--mut)">3.4. Срок рассмотрения заявления службой поддержки составляет <strong style="color:#fff">до 48 часов</strong> (не более 3 рабочих дней).</p>
      <p style="color:var(--mut)">3.5. Выплата денежных средств осуществляется тем же способом, которым производилась оплата: через Систему быстрых платежей (СБП / НСПК) по номеру телефона плательщика либо на банковскую карту. Срок зачисления банком получателя составляет <strong style="color:#fff">от 1 до 3 банковских дней</strong>.</p>

      <h3 style="color:#fff;font-size:17px;margin-top:22px">4. Контакты службы поддержки</h3>
      <p style="color:var(--mut)">
        Электронная почта: <a href="mailto:support@silentconnect.net" style="color:var(--em-t);text-decoration:underline">support@silentconnect.net</a><br> /* PLACEHOLDER */
        Telegram-бот поддержки: <a href="https://t.me/SilentConnectSupport" style="color:var(--em-t);text-decoration:underline" target="_blank" rel="noopener">@SilentConnectSupport</a>
      </p>`
  }
};

function showLegalDoc(docId) {
  if (!LEGAL_DOCS[docId]) docId = 'refund';
  const doc = LEGAL_DOCS[docId];
  $$('#legalNav button').forEach(b => b.classList.toggle('on', b.dataset.doc === docId));
  const container = $('#legalDoc');
  if (container) {
    container.innerHTML = `<h2>${doc.title}</h2><div class="date">${doc.date}</div>${doc.html}`;
  }
  const nav = $('#legalNav');
  if (nav) centerActiveTab(nav);
}
window.showLegalDoc = showLegalDoc;

const legalNav = $('#legalNav');
if (legalNav) {
  setupDraggableTrack(legalNav);
  $$('#legalNav button').forEach(b => {
    b.addEventListener('click', () => showLegalDoc(b.dataset.doc));
  });
}
showLegalDoc('refund');

/* =========================================================================
   Cinematic Intro & Scroll Reveal (.rv)
   Плавное появление из атмосферного затемнения
   ========================================================================= */
function initScrollReveal() {
  const rvs = $$('.rv');
  if (!rvs.length) return;

  if (!('IntersectionObserver' in window)) {
    rvs.forEach(el => el.classList.add('in'));
    return;
  }

  const obs = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        observer.unobserve(entry.target);
      }
    });
  }, {
    rootMargin: '0px 0px -30px 0px',
    threshold: 0.05
  });

  rvs.forEach(el => obs.observe(el));

  // Immediate kick-off for above-the-fold elements
  requestAnimationFrame(() => {
    rvs.forEach(el => {
      const rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight * 0.95) {
        el.classList.add('in');
      }
    });
  });

  // Safety fallback after 1.2s in case of any observer glitch
  setTimeout(() => {
    $$('.rv:not(.in)').forEach(el => {
      const r = el.getBoundingClientRect();
      if (r.top < window.innerHeight) el.classList.add('in');
    });
  }, 1200);
}
window.initScrollReveal = initScrollReveal;

/* =========================================================================
   14. PRODUCTION HYDRATION ADAPTER (window.SC_PROD)
   ========================================================================= */
if (window.SC_PROD) {
  const P = window.SC_PROD;

  // 1. Remove prototype-only lab switchers
  $$('.lab, .lab-group').forEach(el => el.remove());

  // 2. Replace Poland (pl) with Germany (de) in production server list while keeping alias
  AWG_SERVERS.de = {
    code: 'de',
    name: 'Германия',
    city: 'Франкфурт',
    flag: '<span class="flag-badge" aria-label="Германия"><svg width="16" height="11" viewBox="0 0 16 11" fill="none" aria-hidden="true"><rect width="16" height="11" rx="2" fill="#FFCE00"/><rect width="16" height="7.33" rx="2" fill="#DD0000"/><rect width="16" height="3.67" rx="2" fill="#000"/></svg></span>',
    ping: 24
  };
  AWG_SERVERS.pl = AWG_SERVERS.de;

  $$('input[name="awg_country"][value="pl"], input[name="wl_country"][value="pl"]').forEach(inp => {
    inp.value = 'de';
    const row = inp.closest('label');
    if (row) {
      const b = row.querySelector('b');
      if (b) b.innerHTML = `${AWG_SERVERS.de.flag} Германия (Франкфурт)`;
    }
  });
  const pPlEl = $('#pPl');
  if (pPlEl && pPlEl.parentElement) {
    pPlEl.parentElement.innerHTML = `<span>${AWG_SERVERS.de.flag}Германия</span><b id="pPl">24 мс</b>`;
  }

  // 3. Cloudflare Turnstile widget replacement
  const tsKey = P.turnstileSiteKey || P.cfTurnstileSiteKey || '';
  $$('.cf-widget').forEach(box => {
    if (tsKey) {
      box.innerHTML = `<div class="cf-turnstile" data-sitekey="${tsKey}" data-theme="dark"></div>`;
    } else {
      box.innerHTML = `<input type="hidden" name="cf-turnstile-response" value="">`;
      box.style.display = 'none';
    }
  });
  if (tsKey && !document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')) {
    const ts = document.createElement('script');
    ts.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    ts.async = true;
    ts.defer = true;
    document.head.appendChild(ts);
  }

  // 4. Cross-page navigation when not on landing page (capture-phase delegation for [data-go] / [data-goto])
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-go="landing"], [data-goto="landing"]');
    if (!el) return;
    if (P.view && P.view !== 'landing') {
      e.preventDefault();
      e.stopImmediatePropagation();
      const href = el.getAttribute('href') || '';
      const scroll = el.dataset.scroll || (href.startsWith('#') && href !== '#top' ? href : '');
      const base = P.publicBaseUrl || P.shopBaseUrl || '/';
      window.location.href = scroll ? `${base.replace(/\/$/, '')}/${scroll}` : base;
    }
  }, true);

  // Hydrate server-side referral / promo on landing
  if (P.refCode) {
    if ($('#fRef')) $('#fRef').value = P.refCode;
    S.refPct = Number(P.discountPercent || 10);
    if ($('#refBanner')) $('#refBanner').hidden = false;
  }
  if (P.promoCode) {
    S.promo = P.promoCode;
    S.promoPct = Number(P.discountPercent || 10);
    S.promoType = S.promoPct >= 100 ? 'gift' : 'pct';
    if ($('#fPromo')) $('#fPromo').value = P.promoCode;
    if (promoInput) promoInput.value = P.promoCode;
  }
  if (P.refCode || P.promoCode) renderCatalog();

  // 5. Real Promo Code API (/api/check-promo)
  if (promoApplyBtn) {
    promoApplyBtn.addEventListener('click', async e => {
      e.preventDefault();
      e.stopImmediatePropagation();
      if (!promoInput) return;
      const code = promoInput.value.trim().toUpperCase();
      const fPromo = $('#fPromo');
      if (!code) {
        S.promo = ''; S.promoPct = 0; S.promoType = null;
        if (fPromo) fPromo.value = '';
        if (promoMsg) { promoMsg.className = 'promo-msg'; promoMsg.textContent = 'Введите промокод или подарочный сертификат.'; }
        renderCatalog();
        return;
      }
      try {
        const resp = await fetch('/api/check-promo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, plan: String(S.dev), months: S.months })
        });
        const data = await resp.json();
        if (resp.ok && (data.ok || data.valid)) {
          S.promo = code;
          S.promoPct = data.type === 'gift' ? 100 : Number(data.discount_percent ?? data.discount_pct ?? 0);
          S.promoType = S.promoPct >= 100 ? 'gift' : 'pct';
          if (fPromo) fPromo.value = code;
          if (promoMsg) {
            promoMsg.className = 'promo-msg ok';
            promoMsg.textContent = data.message || `✓ Промокод ${code} применён (−${S.promoPct}%)`;
          }
          toast(`Промокод ${code} применён!`);
        } else {
          S.promo = ''; S.promoPct = 0; S.promoType = null;
          if (fPromo) fPromo.value = '';
          if (promoMsg) {
            promoMsg.className = 'promo-msg err';
            promoMsg.textContent = (data && (data.error || data.message)) || '✕ Промокод не найден или устарел';
          }
          toast('Промокод не найден');
        }
      } catch (_) {
        toast('Ошибка проверки промокода');
      }
      renderCatalog();
    }, true);
  }

  // 6. Real Order Form submission (POST /order)
  if (orderForm) {
    orderForm.addEventListener('submit', e => {
      const emailField = $('#email');
      const email = (emailField ? emailField.value : '').trim();
      if (!email || !email.includes('@')) {
        e.preventDefault();
        e.stopImmediatePropagation();
        if (emailField) emailField.classList.add('err');
        const err = $('#emailErr');
        if (err) err.hidden = false;
        toast('Укажите корректный Email для получения ключа');
        return;
      }
      if ($('#fDevices')) $('#fDevices').value = String(S.dev);
      if ($('#fMonths')) $('#fMonths').value = String(S.months);
      if ($('#fPromo')) $('#fPromo').value = S.promo || (promoInput ? promoInput.value.trim() : '');
      e.stopImmediatePropagation();
    }, true);
  }

  // 7. Real Cabinet Magic Link request (POST /api/cabinet/request-link)
  if (cabinetForm) {
    cabinetForm.addEventListener('submit', async e => {
      e.preventDefault();
      e.stopImmediatePropagation();
      const emailEl = $('#cabinetEmail') || $('#cabinetForm input[type="email"]');
      const email = (emailEl ? emailEl.value : '').trim();
      if (!email || !email.includes('@')) {
        toast('Укажите корректный Email');
        return;
      }
      const tsInput = cabinetForm.querySelector('[name="cf-turnstile-response"]');
      const cfToken = tsInput ? tsInput.value : '';
      try {
        toast('Отправляем ссылку для входа…');
        const resp = await fetch('/api/cabinet/request-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, turnstile_token: cfToken, 'cf-turnstile-response': cfToken })
        });
        const data = await resp.json().catch(() => ({}));
        if (resp.ok && data.ok !== false) {
          closeAllModals();
          toast(data.message || '✓ Ссылка для входа отправлена на вашу почту!');
        } else {
          toast((data && (data.error || data.message)) || 'Не удалось отправить ссылку');
        }
      } catch (_) {
        toast('Ошибка соединения с сервером');
      }
    }, true);
  }

  // 8. View-specific hydration
  if (P.errorMessage) {
    setTimeout(() => toast(P.errorMessage), 150);
  }

  if (P.view === 'legal') {
    showLegalDoc(P.legalDoc || 'about');
    view('legal');
  } else if (P.view === 'order' && P.order) {
    const O = P.order;
    if ($('#ordIdTitle')) $('#ordIdTitle').textContent = O.publicId || '';
    if ($('#ordPlanName')) $('#ordPlanName').textContent = O.planLabel || '';
    if ($('#ordDuration')) $('#ordDuration').textContent = O.durationLabel || '';
    if ($('#ordAwg')) $('#ordAwg').textContent = O.awgLabel || '';
    if ($('#ordEmail')) $('#ordEmail').textContent = O.emailMasked || '—';
    if ($('#ordTotal')) $('#ordTotal').textContent = `${fmt(O.amountRub || 0)} ₽`;
    if ($('#payBtnSum')) $('#payBtnSum').textContent = `${fmt(O.amountRub || 0)} ₽`;
    if ($('#ordUrlInput')) $('#ordUrlInput').value = O.orderUrl || window.location.href; if ($('#orderSelfLink')) $('#orderSelfLink').value = O.orderUrl || window.location.href; if ($('#subKeyLink') && O.subscriptionUrl) $('#subKeyLink').value = O.subscriptionUrl;
    if ($('#ordClaimTgBtn') && O.claimUrl) $('#ordClaimTgBtn').href = O.claimUrl;

    if (O.protectedNotice) {
      const waitBox = $('#ordActionWaiting') || $('#ordWait');
      if (waitBox) {
        waitBox.innerHTML = `<div class="card card-pad" style="border-color:rgba(245,158,11,.35)">
          <h3 style="font-size:19px;margin-bottom:8px">Доступ к заказу защищен</h3>
          <p style="font-size:13.5px;color:var(--mut);line-height:1.6">${O.protectedMessage || 'Откройте полную секретную ссылку заказа из вашего браузера или письма на электронной почте.'}</p>
        </div>`;
      }
    } else {
      const payBtn = $('#payBtn');
      if (payBtn) {
        payBtn.addEventListener('click', e => {
          e.stopImmediatePropagation();
          if (O.paymentUrl && O.paymentUrl !== '#') {
            window.location.href = O.paymentUrl;
          } else {
            e.preventDefault();
            toast('Ссылка на оплату формируется, обновите страницу через пару секунд');
          }
        }, true);
        if (O.paymentUrl) payBtn.href = O.paymentUrl;
      }

      const cancelBtn = $('#cancelOrdBtn');
      if (cancelBtn && O.cancelUrl) {
        cancelBtn.addEventListener('click', e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          const f = document.createElement('form');
          f.method = 'POST';
          f.action = O.cancelUrl;
          document.body.appendChild(f);
          f.submit();
        }, true);
      }

      const goSubBtn = $('#ordGoSubBtn');
      if (goSubBtn && O.setupUrl) {
        goSubBtn.removeAttribute('data-goto');
        goSubBtn.addEventListener('click', e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          window.location.href = O.setupUrl;
        }, true);
      }

      if (O.state === 'waiting' && O.statusPollUrl) {
        setInterval(async () => {
          try {
            const r = await fetch(O.statusPollUrl, { headers: { 'Accept': 'application/json' } });
            if (!r.ok) return;
            const d = await r.json();
            if (d.status && d.status !== 'waiting_payment' && d.status !== 'pending') {
              window.location.reload();
            }
          } catch (_) {}
        }, 4000);
      }
    }

    setOrderState(O.state || 'waiting');
    view('order');
  } else if (P.view === 'cabinet' && P.cabinet) {
    const C = P.cabinet;
    if ($('#cabSessionEmail')) $('#cabSessionEmail').textContent = C.email || '';
    if ($('#cabStatsCount')) $('#cabStatsCount').textContent = String((C.items || []).length);
    const grid = $('#view-cabinet .cab-grid');
    if (grid && Array.isArray(C.items)) {
      if (C.items.length === 0) {
        grid.innerHTML = `<div class="card card-pad" style="grid-column:1/-1"><h3 style="font-size:18px;margin-bottom:6px">Подписки не найдены</h3><p style="color:var(--mut);font-size:14px">На эту почту пока нет активных или архивных подписок.</p></div>`;
      } else {
        grid.innerHTML = C.items.map((item, idx) => `
          <div class="card cab-card ${item.isActive ? 'active-sub' : ''}" ${!item.isActive ? 'style="opacity:.86"' : ''}>
            <div class="cab-card-head">
              <h3>Подписка #${idx + 1} · ${item.planTitle || 'Тариф'}</h3>
              <span class="status ${item.statusClass || 'ok'}"><i></i>${item.statusText || 'Активна'}</span>
            </div>
            <div class="ord-rows">
              <div class="ord-row"><span>Лимит устройств</span><b>до ${item.devices || 3} устройств</b></div>
              <div class="ord-row"><span>Пакет AmneziaWG</span><b>${item.awgLabel || '250 ГБ / мес'}</b></div>
              <div class="ord-row"><span>Действует до</span><b>${item.expiresLabel || '—'}</b></div>
              <div class="ord-row"><span>ID профиля</span><b class="mono">${item.subId || ''}</b></div>
            </div>
            <div style="margin-top:auto;padding-top:6px">
              <a href="${item.setupUrl || '#'}" class="btn btn-primary btn-block" style="height:44px">Мастер настройки и подключения <svg class="btn-arrow" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4"/></svg></a>
            </div>
          </div>
        `).join('');
      }
    }
    view('cabinet');
  } else if (P.view === 'sub' && P.sub) {
    const Sub = P.sub;
    SUB_ID = Sub.subId || SUB_ID;
    SUB_URL = Sub.subUrl || SUB_URL;
    SUB_IMPORT_URL = Sub.subImportUrl || SUB_URL;
    if (Sub.importBase) IMPORT_BASE = Sub.importBase;
    if (Sub.importLinks && typeof Sub.importLinks === 'object') APP_IMPORT_URLS = Sub.importLinks;

    if ($('#subHeroId')) $('#subHeroId').textContent = SUB_ID;
    if ($('#subStatusBadge')) {
      $('#subStatusBadge').className = `status ${Sub.isExpired ? 'err' : 'ok'}`;
      $('#subStatusBadge').innerHTML = `<i></i>${Sub.statusLabel || (Sub.isExpired ? 'Истекла' : 'Активна')}`;
    }
    if ($('#subPlanBadge')) $('#subPlanBadge').textContent = Sub.planBadge || 'Тариф';
    if ($('#subDaysLeft')) $('#subDaysLeft').textContent = Sub.daysLeftLabel || '';
    if ($('#subExpireDate')) $('#subExpireDate').textContent = Sub.expireDateLabel || '';
    if ($('#subDevicesLimit')) $('#subDevicesLimit').textContent = Sub.devicesLimitLabel || '';
    if ($('#subUrlInput')) $('#subUrlInput').value = SUB_URL;
    if ($('#copyMainImportBtn')) $('#copyMainImportBtn').dataset.copyUrl = SUB_URL;
    if ($('#subBotLink') && Sub.botUrl) $('#subBotLink').href = Sub.botUrl;
    if ($('#subPartnerBotLink') && Sub.partnerBotUrl) $('#subPartnerBotLink').href = Sub.partnerBotUrl;
    if ($('#subMetricPlan')) {
      const pBadge = Sub.planBadge || 'Личный';
      const devRaw = String(Sub.devicesLimitLabel || Sub.deviceLimit || 'до 3 устр.');
      const devShort = devRaw.replace(/устройств(а)?/, 'устр.').trim();
      $('#subMetricPlan').textContent = `${pBadge} · ${devShort}`;
    }
    if ($('#subMetricExpires')) {
      const dLabel = (Sub.daysLeftLabel || '').trim();
      const eLabel = (Sub.expireDateLabel || '').trim();
      const isUnlimited = !Sub.isExpired && (eLabel.toLowerCase().includes('огранич') || dLabel.toLowerCase().includes('огранич') || (!Sub.expireAt && !Sub.expiresAt && !eLabel && !dLabel));
      if (isUnlimited) {
        $('#subMetricExpires').textContent = 'Без ограничений';
      } else if (eLabel && dLabel && !eLabel.includes(dLabel)) {
        $('#subMetricExpires').textContent = `${eLabel} (${dLabel})`;
      } else if (eLabel) {
        $('#subMetricExpires').textContent = eLabel;
      } else if (dLabel) {
        $('#subMetricExpires').textContent = dLabel;
      } else {
        $('#subMetricExpires').textContent = 'Активна';
      }
    }
    const tRaw = Sub.trafficLabel || '∞';
    const tClean = tRaw.replace(/\s*·\s*безлимит/gi, '').trim();
    if ($('#subMetricMainTraffic')) $('#subMetricMainTraffic').textContent = tClean || '∞';
    if ($('#renewRemainDaysNote')) {
      $('#renewRemainDaysNote').textContent = (!Sub.isExpired && Sub.daysLeftLabel) ? `суммируются с вашим остатком (${Sub.daysLeftLabel})` : 'активируются сразу после оплаты';
    }
    if (Sub.deviceLimit && [3, 6, 9].includes(Number(Sub.deviceLimit))) {
      S.renDev = Number(Sub.deviceLimit);
      renderRenewCalculations();
    }

    if ($('#rawClashLink') && Sub.clashUrl) $('#rawClashLink').href = Sub.clashUrl;
    if ($('#rawSbLink') && Sub.singboxUrl) $('#rawSbLink').href = Sub.singboxUrl;
    if ($('#rawV2Link') && Sub.v2rayUrl) $('#rawV2Link').href = Sub.v2rayUrl;

    S.emailBound = Boolean(Sub.emailBound);
    syncRenewEmailState();
    if ($('#renewEmailInput')) {
      $('#renewEmailInput').value = Sub.customerEmail || '';
    }
    if (Sub.emailBound && Sub.boundEmailMasked) {
      if ($('#subBoundEmail')) $('#subBoundEmail').textContent = Sub.boundEmailMasked;
      if ($('#boundEmailLabel')) $('#boundEmailLabel').textContent = Sub.boundEmailMasked;
    }

    if (Sub.flashHtml) {
      const wrapEl = $('#view-sub .container') || $('#view-sub .wrap');
      if (wrapEl) {
        const flashDiv = document.createElement('div');
        flashDiv.className = 'sc-prod-flash';
        flashDiv.style.marginBottom = '18px';
        flashDiv.innerHTML = Sub.flashHtml;
        wrapEl.insertBefore(flashDiv, wrapEl.firstChild);
      }
    }

    // Hydrate AWG slots & quota
    if (Sub.awg) {
      const Awg = Sub.awg;
      if ($('#awgRemainingText')) $('#awgRemainingText').textContent = Awg.remainingLabel || '—';
      if ($('#awgTotalText')) $('#awgTotalText').textContent = Awg.totalLabel || '';
      if ($('#awgPctText')) $('#awgPctText').textContent = `${Awg.percentRemaining ?? 100}% доступно`;
      if ($('#awgQuotaFill')) $('#awgQuotaFill').style.width = `${Awg.percentRemaining ?? 100}%`;
      if ($('#awgResetDate')) $('#awgResetDate').textContent = Awg.resetLabel ? `сброс ${Awg.resetLabel}` : 'сброс 1-го числа';
      const remNum = (Awg.remainingLabel || '250').replace(/\s*ГБ/gi, '').trim();
      if ($('#subMetricAwgQuota')) $('#subMetricAwgQuota').textContent = `${remNum} / ${Awg.packageGb || 250} ГБ`;

      if (Array.isArray(Awg.slots) && Awg.slots.length > 0) {
        AWG_SLOTS.length = 0;
        Awg.slots.forEach(s => {
          AWG_SLOTS.push({
            id: s.index,
            name: s.name || `Устройство ${s.index}`,
            server: s.country || 'nl',
            ip: s.address || `10.8.0.${s.index + 1}`,
            active: s.active !== false,
            confUrl: s.confUrl,
            qrUrl: s.qrUrl,
            configText: s.configText || ''
          });
        });
      }

      window.downloadSlotConf = function(slotId) {
        const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
        if (slot && slot.confUrl) {
          window.location.href = slot.confUrl;
          return;
        }
        if (slot && slot.configText) {
          const blob = new Blob([slot.configText], { type: 'text/plain;charset=utf-8' });
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = `silentconnect-slot-${slot.id}.conf`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
        }
      };

      window.copySlotConf = async function(slotId) {
        const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
        if (!slot) return;
        if (slot.configText) {
          copyToClipboard(slot.configText, `Конфигурация слота #${slot.id} скопирована!`);
        } else if (slot.confUrl) {
          try {
            const r = await fetch(slot.confUrl);
            const t = await r.text();
            slot.configText = t;
            copyToClipboard(t, `Конфигурация слота #${slot.id} скопирована!`);
          } catch (_) {
            toast('Не удалось загрузить конфигурацию слота');
          }
        }
      };

      window.openSlotQrModal = async function(slotId) {
        const slot = AWG_SLOTS.find(s => s.id === slotId) || AWG_SLOTS[0];
        if (!slot) return;
        const qrImg = slot.qrUrl ? `${slot.qrUrl}${slot.qrUrl.includes('?') ? '&' : '?'}t=${Date.now()}` : '';
        openQrModal(`QR-код: ${slot.name}`, `AmneziaWG · Слот #${slot.id} (${(slot.server || 'nl').toUpperCase()})`, qrImg);
      };

      window.promptRenameSlot = async function(slotId) {
        const slot = AWG_SLOTS.find(s => s.id === slotId);
        if (!slot) return;
        const nextName = prompt('Введите название устройства для этого слота:', slot.name);
        if (!nextName || !nextName.trim()) return;
        const clean = nextName.trim().slice(0, 32);
        if (Awg.apiBase) {
          try {
            const r = await fetch(`${Awg.apiBase}/slot/${slot.id}/rename`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ slot_label: clean, label: clean, name: clean })
            });
            if (r.ok) {
              slot.name = clean;
              renderAwgSetup();
              toast('Название слота обновлено');
              return;
            }
          } catch (_) {}
        }
        slot.name = clean;
        renderAwgSetup();
      };

      if (awgApplyBtn && Awg.apiBase) {
        awgApplyBtn.addEventListener('click', async e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          const checked = $('input[name="awg_country"]:checked');
          const code = checked ? checked.value : 'nl';
          const slot = AWG_SLOTS.find(s => s.id === S.awgTargetSlot);
          closeAllModals();
          if (!slot) return;
          try {
            toast('Переключаем сервер слота…');
            const r = await fetch(`${Awg.apiBase}/slot/${slot.id}/switch_country`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ country: code, server_code: code })
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok && d.ok !== false) {
              slot.server = code;
              slot.configText = d.config || '';
              renderAwgSetup();
              const srv = AWG_SERVERS[code] || AWG_SERVERS.nl;
              toast(`✓ Слот переключён на ${srv.name}! Скачайте новый .conf`);
            } else {
              toast((d && (d.error || d.message)) || 'Ошибка смены сервера');
            }
          } catch (_) {
            toast('Ошибка соединения при смене сервера');
          }
        }, true);
      }
      renderAwgSetup();
    }

    // Hydrate OpenFlux state & API
    if (Sub.openflux) {
      const Of = Sub.openflux;
      S.ofCountry = Of.country || 'nl';
      S.ofTargetCountry = Of.targetCountry || 'de';
      S.ofKeyUri = Of.keyUri || '';
      S.ofNewKeyUri = Of.newKeyUri || '';
      if (typeof Of.remainingSeconds === 'number' && Of.remainingSeconds > 0) {
        ofTimeRemaining = Of.remainingSeconds;
      }
      setOfState(Of.state || 'inactive');
      if (Of.keyUri) {
        if ($('#ofKeyInput')) $('#ofKeyInput').value = Of.keyUri;
        if ($('#ofTopDeeplinkBtn')) $('#ofTopDeeplinkBtn').href = Of.keyUri;
        if ($('#ofImportBtn')) $('#ofImportBtn').href = Of.keyUri;
      }
      if (Of.newKeyUri) {
        if ($('#ofNewKeyInput')) $('#ofNewKeyInput').value = Of.newKeyUri;
        if ($('#ofNewTopDeeplinkBtn')) $('#ofNewTopDeeplinkBtn').href = Of.newKeyUri;
      }

      const ofCancelBtn = $('#ofCancelMigBtn');
      if (ofCancelBtn && Of.apiBase) {
        ofCancelBtn.addEventListener('click', async e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          try {
            const r = await fetch(`${Of.apiBase}/switch/cancel`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({})
            });
            if (r.ok) window.location.reload();
            else toast('Не удалось отменить переход');
          } catch (_) {
            toast('Ошибка соединения с сервером');
          }
        }, true);
      }

      if (wlConfirmPickBtn && Of.apiBase) {
        wlConfirmPickBtn.addEventListener('click', async e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          const checked = $('input[name="wl_country"]:checked');
          const targetCode = checked ? checked.value : 'de';
          closeAllModals();
          const endpoint = S.ofState === 'inactive' ? `${Of.apiBase}/activate` : `${Of.apiBase}/switch/prepare`;
          try {
            toast('Подготавливаем выделенный слот OpenFlux…');
            const r = await fetch(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ target: targetCode, target_country: targetCode, country: targetCode })
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok && d.ok !== false) {
              window.location.reload();
            } else {
              toast((d && (d.error || d.message)) || 'Не удалось переключить слот OpenFlux');
            }
          } catch (_) {
            toast('Ошибка соединения с сервером');
          }
        }, true);
      }

      if (ofFinalizeBtn && Of.apiBase) {
        ofFinalizeBtn.addEventListener('click', async e => {
          e.preventDefault();
          e.stopImmediatePropagation();
          closeAllModals();
          try {
            const r = await fetch(`${Of.apiBase}/switch/confirm`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({})
            });
            if (r.ok) window.location.reload();
            else toast('Не удалось подтвердить переход');
          } catch (_) {
            toast('Ошибка соединения с сервером');
          }
        }, true);
      }
    }

    // Hydrate Renew / Bind Email Form
    if (renForm) {
      renForm.addEventListener('submit', e => {
        const mailInput = $('#renewEmailInput');
        const mail = (mailInput ? mailInput.value : '').trim();
        if (!mail || !mail.includes('@')) {
          e.preventDefault();
          e.stopImmediatePropagation();
          toast('Укажите корректный адрес электронной почты');
          if (mailInput) mailInput.focus();
          return;
        }
        e.preventDefault();
        e.stopImmediatePropagation();
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = S.bindOnly
          ? (Sub.bindEmailActionUrl || window.location.pathname.replace(/\/(setup|import)\//, '/bind-email/'))
          : (Sub.renewActionUrl || window.location.pathname.replace(/\/(setup|import)\//, '/renew/'));
        const addField = (k, v) => {
          const inp = document.createElement('input');
          inp.type = 'hidden';
          inp.name = k;
          inp.value = String(v);
          form.appendChild(inp);
        };
        addField('customer_email', mail); addField('email', mail);
        const remChk = renForm.querySelector('input[type="checkbox"]:not(#bindEmailOnly)');
        addField('email_reminders', (!remChk || remChk.checked) ? '1' : '0');
        if (!S.bindOnly) {
          addField('device_limit', S.renDev); addField('duration_days', CFG.days[S.renMonths] || 180); addField('devices', S.renDev);
          addField('months', S.renMonths);
          const rPromo = $('#renewPromoInput');
          if (rPromo && rPromo.value.trim()) addField('promo_code', rPromo.value.trim());
        } else {
          addField('bind_email_only', '1');
        }
        const ts = renForm.querySelector('[name="cf-turnstile-response"]');
        if (ts && ts.value) addField('cf-turnstile-response', ts.value);
        document.body.appendChild(form);
        form.submit();
      }, true);
    }

    renderMainSetup();
    view('sub');
  } else {
    view('landing');
  }
}
initScrollReveal();

})();
