# SilentConnect High-Availability, Disaster Recovery & Emergency Fallback Architecture

Документ фиксирует результаты проектирования, внедрения и боевого тестирования инфраструктуры катастрофоустойчивости SilentConnect, проведённого 1 сентября 2026 года.

---

## 1. Топология кластера (Active-Passive)

```
                       ┌─────────────────────────────────────┐
                       │  Cloudflare DNS (⚪ DNS-Only TTL 60s)│
                       │     silentconnect.net / sub. / edge. │
                       └──────────────────┬──────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  │ (Штатно: 193.233.210.189)                      │ (Авария: 95.217.178.48)
                  ▼                                               ▼
     ┌─────────────────────────┐                     ┌─────────────────────────┐
     │   NL Master (Primary)   │                     │  FI Standby (Secondary) │
     │     193.233.210.189     │                     │      95.217.178.48      │
     ├─────────────────────────┤                     ├─────────────────────────┤
     │ • vpn-shop-silentconnect│                     │ • vpn-shop-silentconnect│
     │   (Telegram-бот) [ACTIVE]│                     │   (Telegram-бот)[STOPPED]
     │ • vpn-shop-web (Сайт /  │                     │ • vpn-shop-web (Сайт /  │
     │   Чекаут :3090) [ACTIVE]│                     │   Чекаут :3090)[STOPPED]│
     │ • Litestream Master     │─── WAL over SFTP ──>│ • Litestream Standby   │
     │   (WAL Streaming)       │                     │   (Restore-Only Replica)│
     │ • Xray-core (:443 Reality│                    │ • Xray-core (:443 Reality│
     │   & Hysteria2) [ACTIVE] │                     │   & Hysteria2) [ACTIVE] │
     │ • Caddy (:4430, :80)    │                     │ • Caddy (:4430, :80)    │
     │ • SubJSON API (:3088)   │                     │ • SubJSON API (:3088)   │
     └─────────────────────────┘                     └─────────────────────────┘
```

---

## 2. Итоги боевого тестирования (1 сентября 2026 г.)

### 2.1. Теневой тест (Shadow Disaster Recovery Test)
- Проведён в изолированной песочнице `/tmp/shadow_test_sandbox/` на сервере FI без прерывания боевого мастера NL.
- **5/5 этапов пройдены успешно**:
  1. Восстановление реплик Litestream (`vpn_shop.db` и `x-ui.db`) ➔ `PRAGMA integrity_check: ok`.
  2. Изолированный запуск `vpn-shop-web` на порту 3090 FI ➔ `HTTP 200 OK`.
  3. Симуляция аварийных транзакций (создание заказов во время ЧС).
  4. 3-Way бесконфликтное слияние данных через `failback_merge.py` ➔ 0 ошибок, сохранение целостности внешних ключей.
  5. Очистка песочницы и возвращение FI в строгий режим Standby.

### 2.2. Полномасштабный боевой тест с переключением (Live Failover Drill)
- **Phase 1 (Promote to FI)**:
  - Остановка control-plane на NL.
  - Запуск `/usr/local/bin/promote_fi.sh` на FI.
  - Автоматическое переключение DNS через `cf-failover-dns.sh` на IP Финляндии (`95.217.178.48`).
  - Telegram-бот и подписки поднялись на сервере FI за 18 секунд.
  - **Ключевой результат для пользователей**: Клиенты с авто-конфигом (Smart URL-Test / Fallback group) автоматически переключили трафик на ноду FI без разрыва интернет-соединения!
- **Phase 2 (Failback to NL)**:
  - Запуск `/usr/local/bin/demote_fi.sh` на FI.
  - 30-секундный Debounce-тест доступности NL.
  - Включение Quiesce Lock на SubJSON FI.
  - 3-Way слияние баз данных на NL (`failback_merge.py`).
  - Автоматический возврат Cloudflare DNS на NL (`193.233.210.189`).
  - Запуск сервисов на NL, снятие блокировок, перевод кластера в статус `NL_PRIMARY`.
  - **Целостность данных**: `PRAGMA integrity_check: ok`, 0 потерянных байт.

---

## 3. Выявленные сетевые нюансы в РФ и применённые решения

1. **IPv6 AAAA Блокировка**:
   - *Проблема*: Зарубежный IPv6 адрес Hetzner Finland (`2a01:4f9:c011:90c6::1`) дропался ТСПУ у российских провайдеров, вызывая зависание полосы загрузки браузера на 20 секунд.
   - *Решение*: Из DNS Cloudflare удалена AAAA-запись, оставлен чистый, быстрый IPv4 (`95.217.178.48`).
2. **Cloudflare Turnstile Graceful Fallback**:
   - *Проблема*: Виджет Turnstile привязан к домену `silentconnect.net`. На резервных или блокируемых доменах отсутствие токена блокировало кнопку оплаты.
   - *Решение*: В `web.py` внедрён Graceful Fallback — если скрипт Turnstile заблокирован провайдером или домен не совпадает, форма не блокирует покупку, а успешно создаёт заказ.
3. **Кэширование DNS российскими провайдерами**:
   - *Проблема*: Рекурсивные DNS-резолверы МТС, Ростелекома и Билайна держат старый IP до 5–10 минут, даже если в Cloudflare выставлен TTL 60 сек.
   - *Решение*: Архитектура аварийного буфера **Vercel Anycast Edge Emergency Buffer**.

---

## 4. Схема Vercel Emergency Buffer (Zero-Waste On-Demand)

Чтобы не расходовать лимиты бесплатного тарифа Vercel и не добавлять сетевой задержки в штатном режиме, Vercel используется **строго как аварийный шлюз**:

```
🟢 ШТАТНЫЙ РЕЖИМ (99.9% времени):
   Браузер / Приложение ────(Прямой DNS)────> NL Master (193.233.210.189)
   [Vercel СПИТ — 0 запросов, 0 потраченных лимитов]

🔴 АВАРИЙНЫЙ РЕЖИМ (Падение NL):
   1. promote_fi.sh активирует аварийный тумблер.
   2. Браузер в РФ ──> Vercel Anycast Edge ──(0 сек ожидания DNS)──> FI Standby (95.217.178.48)
   [Vercel работает как непробиваемый щит от ТСПУ и исключает DNS-задержку]

🔄 ВОЗВРАТ (Failback):
   1. demote_fi.sh переводит DNS обратно на NL.
   2. [Vercel снова ЗАСЫПАЕТ]
```

### Безопасность IP в Vercel:
- Боевые IP-адреса серверов (`NL_ORIGIN`, `FI_ORIGIN`) хранятся **исключительно в зашифрованных Environment Variables проекта Vercel** и никогда не публикуются в открытом коде.

---

## 5. Сводка исполняемых скриптов (Runbooks)

| Скрипт | Расположение | Назначение |
| :--- | :--- | :--- |
| `promote_fi.sh` | `/usr/local/bin/promote_fi.sh` (FI) | Восстанавливает базу из реплики, запускает сервисы на FI, переключает DNS на FI. |
| `demote_fi.sh` | `/usr/local/bin/demote_fi.sh` (FI) | Включает Quiesce, передает дельту на NL, запускает 3-way merge, возвращает DNS на NL. |
| `cf-failover-dns.sh` | `/usr/local/bin/cf-failover-dns.sh` (NL/FI) | Автоматизация Cloudflare API (A-записи DNS-Only ⚪ для `silentconnect.net`, `sub.`, `edge.`). |
| `failback_merge.py` | `/usr/local/bin/failback_merge.py` (NL/FI) | 3-Way движок слияния SQLite (`orders`, `profiles`, `telegram_users`, `inbounds`, `client_traffics`). |
| `cf-failover-dns.env` | `/etc/cf-failover-dns.env` (NL/FI) | Защищённый конфиг токена Cloudflare (`chmod 600`). |
