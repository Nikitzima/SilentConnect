# vpn-shop

Telegram-магазин для SilentConnect поверх `3X-UI` и `subjson-service`.

## Главная Документация

Подробная карта системы, серверные пути, сценарии покупки, пробники, рефералка, импорт, деплой и восстановление описаны в [docs/SILENTCONNECT_RUNBOOK.md](docs/SILENTCONNECT_RUNBOOK.md).

## Что Уже Есть

- открытая витрина `/start` с тарифами, FAQ, правилами, приватностью и поддержкой;
- покупка gated: смотреть витрину можно без инвайта, создавать платный заказ можно только с допуском;
- промокоды могут запускать сценарий без инвайта;
- ручное подтверждение оплаты через админский Telegram-flow;
- выдача ссылки только после оплаты или 100% промокода;
- админ не видит полную subscription-ссылку клиента в интерфейсе;
- ссылка не хранится в базе магазина, а собирается при доставке через `subjson-service`;
- одно активное незавершенное оформление на чат, self-cancel и автоистечение `waiting_payment` через 6 часов;
- промокоды `anonymous` и `family`, семейные промокоды требуют отдельного согласия;
- 24h тестовые профили и личный админ-конфиг;
- опциональные welcome/quickstart картинки через `WELCOME_MEDIA` и `QUICKSTART_MEDIA`.

## Локальный Старт

```powershell
cd .\vpn-shop
Copy-Item .env.example .env
python -m vpn_shop init-db
python -m vpn_shop create-invite --uses 1 --days 30
python -m vpn_shop create-promo --transport xhttp --days 30 --discount 100 --mode anonymous
python -m vpn_shop run-bot
```

## Staging Нового Бота

`.env` можно оставить как базовую среду с общими настройками XUI и подписок. Для чистого бота SilentConnect используется overlay:

```powershell
python -m vpn_shop --env-file .env.silentconnect run-bot
```

Файл `.env.silentconnect` должен содержать токен нового бота и значения, которые нужно переопределить:

```text
TELEGRAM_BOT_TOKEN=
TELEGRAM_BOT_USERNAME=SilentConnectVPNBot
BRAND_NAME=SilentConnect
WELCOME_MEDIA=assets/telegram/welcome.png
QUICKSTART_MEDIA=assets/telegram/quickstart.png
```

## Медиа

Картинки можно класть в `assets/telegram/`:

```text
assets/telegram/avatar.png
assets/telegram/welcome.png
assets/telegram/quickstart.png
```

Аватар ставится через BotFather. `welcome.png` и `quickstart.png` бот может отправлять напрямую, если пути указаны в env.

## Продакшен

- `SUBSCRIPTION_BASE_URL` должен смотреть на HTTPS-домен вида `https://sub.example.com/.../json`.
- `PUBLIC_HOST` в `subjson-service` должен быть доменом VPN endpoint, например `edge.example.com`.
- `subjson-service` должен слушать только локально за Caddy, без публичного `:3088`.
- Перед реальным запуском админ должен один раз открыть бота через `/start`, иначе боту некуда отправлять админские кнопки.
