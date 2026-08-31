# SilentConnect: BotFather и медиа

## BotFather

Для нового бота `@SilentConnectVPNBot` выставить:

- `Name`: `SilentConnect`
- `Description`: `Приватный доступ к открытому интернету. Понятное подключение, персональные ссылки и аккуратная поддержка.`
- `About`: `Надежный приватный доступ без лишней сложности.`

Команды:

```text
start - главное меню
prices - тарифы и варианты доступа
help - как подключить
faq - частые вопросы
rules - правила и приватность
support - поддержка
```

Name, Description, About и команды можно выставить через Telegram Bot API; на сервере это уже сделано для staging-бота. Аватарка ставится только через BotFather: `/setuserpic`.

## Медиа В Боте

`WELCOME_MEDIA` и `QUICKSTART_MEDIA` можно оставить пустыми. Тогда бот работает в текстовом режиме.

Поддерживаются три варианта:

- Telegram `file_id` уже загруженной картинки;
- публичный `https://...` URL;
- локальный файл относительно папки `vpn-shop`, например `assets/telegram/welcome.png`.

Рекомендуемые локальные имена:

```text
assets/telegram/avatar.png
assets/telegram/welcome.png
assets/telegram/quickstart.png
```

Пример overlay для нового бота:

```text
BRAND_NAME=SilentConnect
WELCOME_MEDIA=assets/telegram/welcome.png
QUICKSTART_MEDIA=assets/telegram/quickstart.png
```

## Быстрый Порядок

1. В BotFather обновить `Name`, `Description`, `About` и команды.
2. Через `/setuserpic` поставить `assets/telegram/avatar.png`.
3. Положить welcome/quickstart картинки в `assets/telegram/`.
4. Указать пути или `file_id` в `.env.silentconnect`.
5. Запустить staging: `python -m vpn_shop --env-file .env.silentconnect run-bot`.

## Промпты

Актуальные промпты под SilentConnect лежат в `SILENTCONNECT_IMAGE_PROMPTS.txt`.
