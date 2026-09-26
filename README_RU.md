# SilentConnect: Корпоративная мультипротокольная VPN-платформа

[![Версия Python](https://img.shields.io/badge/Python-3.11+-3b82f6.svg?style=flat-square)](https://www.python.org/)
[![Лицензия](https://img.shields.io/badge/License-MIT-64748b.svg?style=flat-square)](LICENSE)
[![Протоколы](https://img.shields.io/badge/Protocols-VLESS_%7C_Reality_%7C_XHTTP_%7C_AmneziaWG_%7C_Hysteria2-8b5cf6.svg?style=flat-square)](#поддержка-протоколов-и-подписок)

**SilentConnect** — высокодоступная мультипротокольная VPN-платформа с автоматизацией подписок. Разработана для противостояния глубокому анализу пакетов (DPI/ТСПУ), манипуляциям с пакетами и отказам инфраструктуры. Платформа объединяет Telegram-бота для продаж, динамическую генерацию подписок в нескольких форматах, провизионинг Xray/3X-UI панелей, управление AmneziaWG WireGuard мешем и active-passive disaster recovery с нулевой потерей данных.

---

## Содержание

1. [Обзор архитектуры](#обзор-архитектуры)
2. [Микросервисы и компоненты](#микросервисы-и-компоненты)
3. [Disaster Recovery и Dual-Node Failover](#disaster-recovery-и-failover)
4. [Поддержка протоколов и подписок](#поддержка-протоколов-и-подписок)
5. [Поддерживаемые платформы и клиентская матрица](#поддерживаемые-платформы-и-клиентская-матрица)
6. [Telegram-бот и административные сценарии](#telegram-бот-и-административные-сценарии)
7. [Веб-магазин и кабинет самообслуживания](#веб-магазин-и-кабинет-самообслуживания)
8. [Конфигурация и каталог переменных окружения](#конфигурация-и-каталог-переменных-окружения)
9. [Деплой и быстрый старт](#деплой-и-быстрый-старт)
10. [Автоматическая безопасность и верификация](#автоматическая-безопасность-и-верификация)

---

## Обзор архитектуры

SilentConnect работает на active-passive географически распределённой multi-node топологии для высокой доступности и мгновенного failover:

```text
                                  [ Пользователи и клиенты ]
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 │                                                   │
      (Браузер / Оформление)                              (VPN-клиенты / Приложения)
                 │                                                   │
      https://example.com                                 https://sub.example.com
                 │                                                   │
      [ Caddy v2 Reverse Proxy ]                          [ Caddy v2 Reverse Proxy ]
                 │                                                   │
      ┌──────────┴──────────┐                             ┌──────────┴──────────┐
      │                     │                             │                     │
[ VPN Shop Web ]    [ Статические файлы ]       [ SubJSON Engine ]    [ Xray Inbounds ]
  (Port 3090)                                        (Port 3088)          (TCP / XHTTP / WS)
      │                                                   │                     │
      └─────────────────────┬─────────────────────────────┘                     │
                            │                                                   │
                     [ SQLite WAL DBs ] <───────────────────────────────────────┘
                     • vpn_shop.db (Состояние и заказы)
                     • x-ui.db (Inbounds и ключи клиентов)
                            │
              [ Непрерывная WAL репликация ]
                            │
                  (Litestream Engine)
                            │
            ┌───────────────┴───────────────┐
            │                               │
   [ Primary Node (NL Master) ]    [ Standby Node (FI Standby) ]
     Subnet: 10.8.1.0/24             Subnet: 10.8.2.0/24
```

### Ключевые архитектурные особенности
- **Разделённые плоскости управления и данных**: Биллинг и система подписок работают независимо от передачи пакетов. VPN-туннели остаются полностью работоспособными даже при обслуживании веб- или бот-сервисов.
- **Устойчивость к DPI**: Комбинация VLESS с XTLS-Reality маскировкой под иностранные SNI (Apple, Google), HTTP/2 мультиплексирование (XHTTP) и обфусцированный AmneziaWG UDP с кастомным пакетным мусором (`Jc`, `Jmin`, `Jmax`) и трансформацией заголовков (`S1`-`S4`, `H1`-`H4`, `I1`-`I5`).
- **Унифицированная модель профилей**: Одна ссылка на подписку динамически рендерит конфигурации для Sing-box, Clash Meta, Happ, Streisand или v2rayN на основе User-Agent.

---

## Микросервисы и компоненты

### 1. `vpn_shop.bot` (Telegram-бот)
- **Путь**: `vpn-shop/vpn_shop/bot.py`
- **Описание**: Высоконадёжный Telegram-бот с детерминистическими конечными автоматами (FSM) для онбординга, выбора тарифа, пробных активаций, промо-скидок и подтверждения оплаты.
- **Ключевые модули**:
  - `ShopBot`: FSM-контроллер управляет контекстами сессий, guards и интерактивными меню.
  - `Provisioner` (`provisioning.py`): Абстракция для взаимодействия с 3X-UI REST API и SQLite БД.
  - `Catalog` (`catalog.py`): Мульти-tier тарифная матрица (3, 6, 9 устройств на 1, 3, 6, 12 месяцев).

### 2. `vpn_shop.web` (Веб-магазин)
- **Путь**: `vpn-shop/vpn_shop/web.py`
- **Описание**: Легковесный async веб-сервер на порту `3090` за Caddy.
- **Функции**:
  - Тёмная адаптивная UI для десктопа и мобильных браузеров.
  - Оплата через СБП QR с real-time статусом.
  - Cloudflare Turnstile защита от ботов.
  - Фоновый worker напоминаний об истечении подписки.

### 3. `subjson-service` (Генератор подписок)
- **Путь**: `subjson-service/app.py`
- **Описание**: High-throughput FastAPI движок на порту `3088` для оптимизированных подписок и веб-мастеров.
- **Функции**:
  - Роуты: `/singbox/{sub_id}`, `/clash/{sub_id}`, `/happ/{sub_id}`, `/v2ray/{sub_id}`.
  - Веб-мастер импорта: `/{SECRET_SEGMENT}/import/{sub_id}`.
  - Standby Quiesce Locking для предотвращения split-brain.
  - Token-Bucket rate limiter (`RATE_LIMIT_RPM=1200`).

### 4. `awg_manager` (AmneziaWG Mesh)
- **Путь**: `vpn-shop/vpn_shop/awg_manager.py`
- **Описание**: Lifecycle manager для обфусцированного AmneziaWG WireGuard mesh.
- **Функции**:
  - Dual-node оркестрация контейнеров.
  - Квотирование трафика (500GB/peer) с автосуспенд и восстановлением.
  - Dynamic AllowedIPs и iptables правила блокировки BitTorrent/DHT.

---

## Disaster Recovery и Failover

```text
        [ Сбой Primary Master (NL) ]
                       │
          (1) Promote Standby: ./promote_fi.sh
              • Восстанавливает последний Litestream snapshot
              • Включает локальные bot, web, subjson сервисы
              • Переключает Cloudflare DNS A-record на Standby IP
                       │
        [ Standby Node обслуживает трафик ]
                       │
        [ Primary Master восстановлен ]
                       │
          (2) Demote & Reconcile: ./demote_fi.sh
              • Acquires Quiesce Lock на Standby
              • Синхронизирует Standby SQLite DBs в Primary staging
              • Executes 3-Way Merge Engine
              • Переключает Cloudflare DNS обратно
```

---

## Поддержка протоколов и подписок

| Формат / Роут | Движок / Протокол | Клиенты | Особенности |
|---|---|---|---|
| `/singbox/<sub_id>` | Sing-box 1.18+ JSON | Sing-box, Happ, Karing | `url-test`, GeoIP/GeoSite routing |
| `/clash/<sub_id>` | Clash Meta / Mihomo YAML | Clash Verge Rev, Mihomo Party | Tun mode, auto latency fallback |
| `/happ/<sub_id>` | Happ Encrypted Bundle | Happ (iOS, Android, Win, Mac, TV) | Auto-update, in-app renewal |
| `/v2ray/<sub_id>` | Base64 Link Bundle | v2rayN, v2rayNG, Streisand | VLESS Reality, XHTTP |

---

## Поддерживаемые платформы и клиентская матрица

| ОС | Рекомендуемый клиент | Альтернативы |
|---|---|---|
| **iOS / iPadOS** | **Happ**, **Streisand** | Shadowrocket, Sing-box |
| **Android** | **Happ**, **v2rayNG** | NekoBox, Sing-box, Flclash |
| **Windows** | **Happ**, **v2rayN** | Clash Verge Rev, Mihomo Party |
| **macOS** | **Happ**, **Clash Verge Rev** | Mihomo Party, Sing-box |
| **Linux** | **Clash Verge Rev** | Mihomo CLI, Sing-box CLI |
| **Android TV** | **Happ (Android TV)** | v2rayNG (TV mode) |
| **Apple TV** | **Streisand**, **Sing-box** | Shadowrocket |

---

## Telegram-бот и административные сценарии

### Пользовательский сценарий
1. Принятие условий (`TERMS_VERSION`)
2. Выбор количества устройств (3, 6, 9)
3. Выбор длительности (30, 90, 180, 360 дней)
4. Бесплатный trial (7 дней для новых пользователей)
5. Промо-коды
6. Оплата через СБП → мгновенная доставка

### Административные команды
- `/admin` — интерактивная панель
- `/status` — диагностика системы
- `/traffic` — топ-20 по трафику
- `/invite` — генерация приглашений
- `/promo` — создание промо-кодов
- `/test_tcp` / `/test_xhttp` — временные debug-профили
- `/warp <sub_id>` — AmneziaWG peer management

---

## Тарифы

| Устройства | Трафик | Цена/месяц |
|------------|--------|------------|
| 3 устройства | 250 ГБ | 149 ₽ |
| 6 устройств | 500 ГБ | 199 ₽ |
| 9 устройств | 1000 ГБ | 235 ₽ |

Скидки за длительность:
- 3 месяца: -10%
- 6 месяцев: -20%
- 12 месяцев: -30%

---

## Деплой и быстрый старт

### Требования
- Ubuntu 22.04/24.04 LTS или Debian 12 (x86_64)
- Python 3.11+, SQLite3, Caddy v2, Git, Docker, Systemd

### Шаг 1: Установка
```bash
git clone https://github.com/your-org/silentconnect.git /root/silentconnect
cd /root/silentconnect
cp .env.example .env
# Заполните .env
```

### Шаг 2: 3X-UI
```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```

### Шаг 3: Caddy
```bash
cp scripts/Caddyfile.fi /etc/caddy/Caddyfile
systemctl enable --now caddy
```

### Шаг 4: Systemd сервисы
```bash
cp subjson-service/subjson.service /etc/systemd/system/
systemctl enable --now subjson.service
```

---

## Лицензия

MIT
