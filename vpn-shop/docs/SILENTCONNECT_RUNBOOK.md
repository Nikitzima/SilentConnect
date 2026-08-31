# SilentConnect Runbook

Документ описывает текущее устройство проекта, рабочие сценарии, серверные сервисы и порядок восстановления. Он нужен, чтобы через месяц не вспоминать по переписке, что именно было сделано.

## 1. Текущее Состояние

SilentConnect состоит из двух основных частей:

- `vpn-shop` - Telegram-бот магазина, админка, заказы, пробники, рефералка, промокоды, продления и выдача ссылок.
- `subjson-service` - локальный HTTP-сервис, который читает клиентов из базы `3X-UI` и генерирует JSON-подписки, страницы импорта, legal-страницу и гибридные конфиги.

На сервере оба сервиса работают рядом с `3X-UI` и `Caddy`:

- `vpn-shop-silentconnect.service` - бот.
- `subjson.service` - генератор подписок.
- `vpn-shop-web.service` - сайт покупки без аккаунтов.
- `x-ui` - панель и Xray core.
- `caddy` - HTTPS-прокси для `example.com`, `www.example.com` и `sub.example.com`.
- `fail2ban` - нужен x-ui для работы `limitIp` и контроля превышения лимита одновременных устройств.

В админ-боте есть кнопка `Сервер и трафик`. Она показывает статус основных сервисов, load/RAM/disk, количество TCP-соединений, проверку DNS до Telegram и топ профилей по трафику. Из карточки профиля можно отправить предупреждение владельцу, временно отключить профиль в Xray и включить его обратно без пересоздания подписки.

Основной публичный вход в бота:

```text
https://t.me/YourVPNBot?start=open
```

Это многоразовая ссылка доступа. Персональные одноразовые инвайты тоже остались, но больше не являются единственным способом попасть в магазин.

## 2. Серверная Карта

Основные пути на сервере:

```text
/root/vpn-shop
/root/vpn-shop/.env
/root/vpn-shop/.env.example
/root/vpn-shop/data/vpn_shop.db

/root/subjson-service
/root/subjson-service/app.py
/root/subjson-service/subjson.env.example

/etc/x-ui/x-ui.db
/etc/systemd/system/vpn-shop-silentconnect.service
/etc/systemd/system/vpn-shop-web.service
/etc/systemd/system/subjson.service
```

При работе с сервера с локального ПК желательно подключаться так, чтобы SSH не пытался уйти обратно через VPN:

```powershell
ssh -b 192.168.1.100 root@192.0.2.1
scp -o BindAddress=192.168.1.100 <file> root@192.0.2.1:<path>
```

Проверка статуса:

```bash
systemctl is-active vpn-shop-silentconnect.service subjson.service x-ui caddy
journalctl -u vpn-shop-silentconnect.service -n 100 --no-pager
journalctl -u vpn-shop-web.service -n 100 --no-pager
journalctl -u subjson.service -n 100 --no-pager
```

Перезапуск:

```bash
systemctl restart subjson.service
systemctl restart vpn-shop-silentconnect.service
systemctl restart vpn-shop-web.service
```

## 3. Сайт

Сайт - это web-checkout без аккаунтов. Он нужен для тех, у кого Telegram не открывается без VPN.

Что умеет v1:

- показать тарифы `3 / 6 / 9 устройств`;
- показывать спокойную витрину для обычного пользователя: `Личный`, `Домашний`, `Расширенный`;
- давать тарифный конструктор без перезагрузки страницы: устройства, срок, режим `Стандартный / Универсальный`;
- создать платный заказ;
- сразу показать кнопку оплаты переводом;
- принять кнопку `Оплачено`;
- отправить админу уведомление в Telegram;
- после админского подтверждения открыть страницу выбора устройства и приложения, если покупатель ждёт на странице оплаты;
- при повторном открытии заказа показать одну кнопку `Подключить`;
- дать ссылку для привязки подписки к Telegram-боту.

Чего сайт намеренно не делает:

- не создаёт аккаунты;
- не хранит email/телефон/пароль;
- не выдаёт пробную неделю;
- не делает самостоятельное продление.

Пробная неделя остаётся эксклюзивом Telegram-бота, потому что там есть Telegram `user_id`, по которому можно жёстче ограничить повторное получение. После покупки на сайте пользователь включает VPN, открывает Telegram и нажимает `Привязать в Telegram`; бот привязывает профиль сайта к Telegram-аккаунту, после чего продление работает через бота.

Переменные сайта:

```text
WEB_LISTEN_HOST=127.0.0.1
WEB_LISTEN_PORT=3090
WEB_PUBLIC_BASE_URL=https://example.com
```

## 4. Как Работает Покупка

Пользователь открывает бота, принимает правила и выбирает действие:

- купить доступ;
- продлить подписку;
- взять бесплатную неделю;
- ввести промокод;
- вступить в реферальную программу;
- открыть помощь, FAQ, правила или поддержку.

Покупка сейчас ручная:

1. Пользователь выбирает тариф.
2. Бот создаёт заказ в SQLite.
3. Админу приходит карточка заказа.
4. Пользователь сразу видит кнопку `Оплатить переводом`, переводит деньги и нажимает `Оплачено`.
5. Бот уведомляет админа, что покупатель сообщил об оплате.
6. Админ проверяет счёт и нажимает `Подтвердить оплату`.
7. Бот создаёт или продлевает профиль в `3X-UI`.
8. Пользователь сразу получает страницу подключения с кнопками приложений.

В оплате используется платёжная ссылка `PAYMENT_TRANSFER_URL`. В тексте заказа есть короткая подсказка: приоритетно переводить в МТС Банк, при необходимости можно Ozon Банк или Т-Банк. Номер карты в коде и интерфейсе не хранится и не показывается.

Если заказ висит в `waiting_payment` больше 6 часов, он считается устаревшим. На один чат не создаётся пачка параллельных незавершённых заказов.

## 4. Тарифы И Лимиты Устройств

Сейчас включена тарифная сетка по количеству одновременно активных устройств:

```text
3 устройства  - 100 RUB / 30 дней
6 устройств  - 150 RUB / 30 дней
9 устройств  - 200 RUB / 30 дней
```

Эти варианты есть для:

- `TCP+REALITY` - стандартный вариант;
- `XHTTP` - технический альтернативный вариант, остаётся доступен для промокодов/админских задач;
- `Универсальный` - TCP+REALITY и XHTTP в одной подписке, на 20% дороже обычного тарифа.

Цены универсального режима:

```text
3 устройства  - 120 RUB / 30 дней
6 устройств  - 180 RUB / 30 дней
9 устройств  - 240 RUB / 30 дней
```

Публично гибрид описываем как вариант для максимальной устойчивости на нестабильном интернете. Не используем формулировки про обход блокировок.

Ограничение реализовано через поле `limitIp` в Xray/x-ui. Это не идеальный счётчик физических устройств, а лимит одновременно активных IP:

- два устройства в одной домашней сети могут считаться как один IP;
- мобильный интернет может менять IP;
- это всё равно самый жёсткий штатный механизм, который сейчас есть без отдельной авторизации каждого устройства.

Новые покупки и продления уже получают выбранный лимит. Старые активные профили автоматически не менялись, чтобы случайно не отрезать доступ людям, которые уже пользуются.

Настройки тарифов задаются в env:

```text
MONTHLY_PRICE_3_DEVICES_RUB=100
MONTHLY_PRICE_6_DEVICES_RUB=150
MONTHLY_PRICE_9_DEVICES_RUB=200
DEFAULT_DEVICE_LIMIT=3
```

## 5. Пробная Неделя

Пробник:

- 7 дней;
- транспорт по умолчанию `TCP+REALITY`;
- один раз на Telegram `user_id`;
- профиль помечается как `public_trial_7d_auto_delete`;
- после истечения бот удаляет его из Xray и помечает удалённым в своей базе.

Повторное получение пробника тем же Telegram-аккаунтом блокируется таблицей `trial_redemptions`.

## 6. Продление

Подписка привязывается к Telegram-пользователю через таблицу `profile_owners`.

Кнопка `Продлить подписку` ищет последний профиль пользователя:

- если профиль живой и не удалён, бот предлагает продление;
- если профиль был стёрт, пользователь покупает новый доступ;
- при продлении сохраняется текущий лимит устройств профиля;
- если старый профиль был без лимита, используется `DEFAULT_DEVICE_LIMIT`.

После подтверждения оплаты бот не создаёт новый профиль, а обновляет expiry клиента в `3X-UI`.

Для `Универсального` режима продление обновляет оба профиля: TCP+REALITY и XHTTP. Пользователь всё равно видит одну подписочную ссылку.

## 7. Реферальная Программа

Рефералка v1:

- пользователь нажимает `Реферальная программа`;
- бот создаёт личную ссылку вида `https://t.me/<bot>?start=ref_<code>`;
- новый пользователь прикрепляется к рефереру при первом заходе по этой ссылке;
- самореферал блокируется;
- повторная или задняя привязка блокируется;
- комиссия начисляется после админского подтверждения платного заказа;
- пробники, бесплатные промокоды и заказы с `final_price_rub = 0` комиссию не дают.

Текущие параметры:

```text
Комиссия: 10%
Минимальная выплата: 500 RUB
Ежемесячное напоминание: с 28 числа месяца
```

Выплаты ручные. Админ открывает `Рефералка`, смотрит баланс и нажимает `Отметить выплаченным`. Это создаёт запись в `referral_payouts`, а начисления в `referral_ledger` закрываются.

## 8. Промокоды И Инвайты

CLI-команды:

```bash
cd /root/vpn-shop
python3 -m vpn_shop --env-file .env.silentconnect create-invite --uses 1 --days 30 --note "comment"
python3 -m vpn_shop --env-file .env.silentconnect create-promo --transport tcp --days 30 --discount 100 --mode anonymous
python3 -m vpn_shop --env-file .env.silentconnect create-promo --transport hybrid --days 30 --discount 100 --mode anonymous
python3 -m vpn_shop --env-file .env.silentconnect create-promo --transport tcp --days 30 --discount 100 --mode family --label "family-name"
```

Инвайт даёт доступ к покупке. Публичная ссылка `start=open` тоже даёт доступ, поэтому инвайты сейчас скорее дополнительный инструмент.

Промокоды бывают двух технических типов:

- `готовый доступ` - админ заранее выбирает транспорт, срок, скидку, режим и лимит устройств `3 / 6 / 9 / без лимита`;
- `скидка на любой тариф` - админ выбирает только процент, пользователь вводит код и сам выбирает покупку или продление.

Режимы готового доступа:

- `anonymous` - обычный режим;
- `family` - семейный режим, требует отдельного согласия пользователя.

Скидки в CLI ограничены значениями:

```text
10, 25, 50, 75, 100
```

Для CLI fixed-промокода можно дополнительно указать `--device-limit 3`, `--device-limit 6`, `--device-limit 9` или `--device-limit 0`. Значение `0` означает без лимита по `limitIp`.

## 9. Подключение И Импорт

После оплаты пользователь получает не просто голую ссылку, а одну основную кнопку:

- `Подключить`;
- `Скопировать ссылку`;
- помощь и меню.

Кнопка `Подключить` ведёт на общую страницу:

```text
/<secret>/import/<subscription_id>
```

На этой странице пользователь выбирает систему (`iOS`, `Android`, `Windows`, `macOS`, `Linux`, `Android TV`, `Apple TV`), а страница показывает доступные для неё приложения и инструкции. Happ идёт первым и помечен как рекомендуемый. Streisand подписан как вариант для `iPhone / iPad`.

Все приложения получают одну и ту же JSON-подписку. Разделение по приложениям живёт на странице подключения, а не в боте, чтобы не перегружать пользователя длинным списком кнопок.

Старые прямые страницы приложений сохранены как внутренние переходы общей страницы:

### Happ

Страница:

```text
/<secret>/import/happ/<subscription_id>
```

Логика:

- сервис пробует получить защищённую ссылку через Happ crypto API;
- если получилось, отдаёт `happ://crypt5/...`;
- если не получилось, показывает fallback с копированием ссылки;
- есть кнопки установки для iOS, Android/Google Play, APK для Huawei/устройств без Google Play и Windows.

APK для Huawei:

```text
https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk
```

### Streisand

Страница:

```text
/<secret>/import/streisand/<subscription_id>
```

Используется схема:

```text
streisand://import/<subscription_url>#SilentConnect
```

По тестам на iPhone этот вариант работает и создаёт профиль в приложении.

### V2RayTun

Страница:

```text
/<secret>/import/v2raytun/<subscription_id>
```

Используется схема:

```text
v2raytun://import/<subscription_url>
```

По тестам работает на Android и iOS.

### Hiddify

Hiddify сейчас не считаем целевым приложением. На Android была ошибка вида:

```text
[SingboxParser] unmarshal error: outbounds[0]: unknown outbound type
```

Пока не тратим на него время, потому что Happ, Streisand и V2RayTun закрывают основные сценарии.

## 10. subjson-service

`subjson-service` читает `/etc/x-ui/x-ui.db`, находит клиента по `subscription_id` и собирает клиентский JSON.

Основные endpoints:

```text
/healthz
/legal/terms
/<secret>/legal/terms

/<secret>/json/<subscription_id>
/<secret>/sub/<subscription_id>
/<secret>/json-global/<subscription_id>
/<secret>/sub-global/<subscription_id>
/<secret>/json-google/<subscription_id>
/<secret>/sub-google/<subscription_id>
/<secret>/json-ru-google/<subscription_id>
/<secret>/sub-ru-google/<subscription_id>
/<secret>/json-hybrid/<tcp_subid>~<xhttp_subid>
/<secret>/sub-hybrid/<tcp_subid>~<xhttp_subid>
/<secret>/json-hybrid-google/<tcp_subid>~<xhttp_subid>
/<secret>/raw/<subscription_id>

/<secret>/import/<subscription_id>
/<secret>/import/happ/<subscription_id>
/<secret>/import/streisand/<subscription_id>
/<secret>/import/v2raytun/<subscription_id>
```

`json` сейчас отдаёт `split-ru` конфиг. То есть российские сервисы идут напрямую, а остальное через VPN.

`json-global` нужен для режима, где весь трафик идёт через VPN.

`json-google` и `json-ru-google` оставлены как запасные варианты с Google DNS.

Гибридный конфиг `json-hybrid` собирает два профиля в один клиентский JSON: `TCP+REALITY` и `XHTTP`, с балансером на стороне клиента.

### Happ App Management

`subjson-service` может отдавать Happ management headers вместе с JSON-подпиской. Это позволяет Happ применять настройки приложения при импорте подписки без отдельного Windows-скрипта:

- `profile-title`, `support-url`, `profile-update-interval`, `subscription-userinfo` отдаются всегда, если `HAPP_HEADERS_ENABLED=1`;
- `profile-web-page-url` для подписочных JSON-роутов строится как персональная страница подключения `/import/<subscription_id>` с тем же исходным JSON-роутом в параметре `url`;
- `meta.serverDescription` и `meta.sub-info-*` добавляют в Happ спокойный инфо-блок: описание сервера, остаток срока и кнопку продления через Telegram;
- `HAPP_UNLIMITED_AFTER_DAYS` задаёт порог, после которого очень далёкий expiry показывается как срок без ограничения, чтобы тестовые/служебные профили не выглядели как десятки тысяч дней;
- TUN/system proxy/server resolving/fragmentation/per-app proxy/exclude-routes отдаются только при заданном `HAPP_PROVIDER_ID`;
- `exclude-routes` строится автоматически из outbound `address` в выдаваемом JSON и резолвится в IPv4 `/32`, плюс можно добавить `HAPP_EXTRA_EXCLUDE_ROUTES`.

Для полноценного применения TUN-настроек нужен provider id Happ. Без него Happ может проигнорировать advanced app-management параметры, поэтому `.bat`-настройка остаётся аварийным fallback для Windows.

## 11. Маршрутизация

Текущий основной режим - `split-ru`.

Идея:

- российские сервисы, `.ru`, `.su`, `.рф`, банки, маркетплейсы, госуслуги, Яндекс, VK, 2GIS и похожее идут напрямую;
- сервисы, которые могут ломаться из-за CDN/anycast, перед RU-direct вынесены в proxy-исключения;
- торрент режется по `protocol: bittorrent`, без огромной портянки доменов;
- `domainStrategy` на серверной стороне настроен на IPv4, чтобы не вылезал британский IPv6.
- DNS по умолчанию остаётся Cloudflare в основном `split-ru`; Google DNS держим как запасной пресет, не как дефолт.

По тестам:

- Ozon видит домашний IP и регион;
- Яндекс.Маркет и Госуслуги работают напрямую;
- Яндекс Интернетометр видит домашний IPv4;
- внешние IP-чекеры после IPv4-фикса показывают Нидерланды вместо GB.

## 12. Юридическая Страница

Legal-страница отдаётся `subjson-service`:

```text
https://sub.example.com/legal/terms
```

Бот показывает кнопку ознакомления рядом с подтверждением. Пользователь нажатием подтверждает:

- возраст 18+;
- принятие условий;
- ответственность за собственные действия;
- запрет незаконной активности;
- понимание, что сервис не управляет действиями пользователя в интернете.

В тексте также описана приватность: магазин не хранит историю посещений, содержимое трафика и DNS-запросы пользователей. При этом технические данные, нужные для выдачи доступа, заказов и поддержки, хранятся в SQLite.

Важно: это хороший прикладной текст, но не замена консультации юриста.

## 13. База Данных Магазина

SQLite база содержит:

```text
chat_sessions          - состояния диалогов;
invite_tokens          - инвайты;
promo_codes            - промокоды;
orders                 - заказы;
profiles               - профили, созданные ботом;
profile_owners         - привязка профиля к Telegram user_id;
admin_actions          - журнал админских и системных действий;
telegram_users         - Telegram-пользователи;
trial_redemptions      - использование пробника;
referrers              - участники рефералки;
referral_attributions  - кто к кому прикреплён;
referral_ledger        - начисления;
referral_payouts       - выплаты.
```

Схема создаётся idempotent через `Store.init()`: можно запускать `init-db` на существующей базе без удаления данных.

Бэкап базы:

```bash
mkdir -p /root/deploy-backups/$(date +%Y%m%d-%H%M%S)
cp /root/vpn-shop/data-silentconnect/vpn_shop.db /root/deploy-backups/$(date +%Y%m%d-%H%M%S)/vpn_shop.db
```

На практике лучше делать один timestamp в переменную:

```bash
ts=$(date +%Y%m%d-%H%M%S)
mkdir -p /root/deploy-backups/$ts
cp /root/vpn-shop/data-silentconnect/vpn_shop.db /root/deploy-backups/$ts/vpn_shop.db
cp /root/vpn-shop/.env.silentconnect /root/deploy-backups/$ts/.env.silentconnect
cp /root/subjson-service/subjson.env /root/deploy-backups/$ts/subjson.env
```

## 14. Env-Переменные vpn-shop

Основные:

```text
SHOP_DATA_DIR
SHOP_DB_PATH

TELEGRAM_BOT_TOKEN
TELEGRAM_BOT_USERNAME
BRAND_NAME
SUPPORT_TG_URL
WELCOME_MEDIA
QUICKSTART_MEDIA
ADMIN_TG_USERNAMES
ADMIN_TG_IDS

SUBSCRIPTION_BASE_URL
PAYMENT_INSTRUCTIONS_TEXT
PAYMENT_TRANSFER_URL
PAYMENT_BANK_NOTE

XUI_PANEL_URL
XUI_USERNAME
XUI_PASSWORD
XUI_VERIFY_TLS
XUI_DB_PATH
XUI_XHTTP_INBOUND_ID
XUI_TCP_INBOUND_ID

WEB_LISTEN_HOST
WEB_LISTEN_PORT
WEB_PUBLIC_BASE_URL

MONTHLY_PRICE_XHTTP_RUB
MONTHLY_PRICE_TCP_RUB
MONTHLY_PRICE_3_DEVICES_RUB
MONTHLY_PRICE_6_DEVICES_RUB
MONTHLY_PRICE_9_DEVICES_RUB
DEFAULT_DEVICE_LIMIT

INVITE_REQUIRED
TERMS_VERSION
PURGE_AFTER_DAYS
```

Секреты не хранить в документации. Их источник истины - `.env` и `.env.silentconnect` на сервере.

## 15. Env-Переменные subjson-service

```text
LISTEN_HOST=127.0.0.1
LISTEN_PORT=3088
SECRET_SEGMENT=my-secret-sub  # PLACEHOLDER
PUBLIC_HOST=edge.example.com
PUBLIC_SUBSCRIPTION_ORIGIN=https://sub.example.com
XUI_DB_PATH=/etc/x-ui/x-ui.db
```

`PUBLIC_HOST` используется внутри клиентского VLESS/REALITY-конфига как адрес VPN-сервера. `PUBLIC_SUBSCRIPTION_ORIGIN` используется для веб-страниц подключения и подписочных URL, чтобы Happ-кнопка `i` открывала `sub.example.com`, а не VPN-endpoint. `LISTEN_HOST` должен оставаться `127.0.0.1`, чтобы сервис не торчал наружу без Caddy.

## 16. Деплой Из Локальной Папки

Перед заменой файлов на сервере:

```bash
ts=$(date +%Y%m%d-%H%M%S)
mkdir -p /root/deploy-backups/$ts
cp /root/vpn-shop/vpn_shop/bot.py /root/deploy-backups/$ts/bot.py
cp /root/vpn-shop/vpn_shop/config.py /root/deploy-backups/$ts/config.py
cp /root/vpn-shop/vpn_shop/catalog.py /root/deploy-backups/$ts/catalog.py
cp /root/vpn-shop/vpn_shop/provisioning.py /root/deploy-backups/$ts/provisioning.py
cp /root/vpn-shop/vpn_shop/store.py /root/deploy-backups/$ts/store.py
cp /root/subjson-service/app.py /root/deploy-backups/$ts/subjson-app.py
```

Заливка с Windows:

```powershell
scp -o BindAddress=192.168.1.100 .\vpn-shop\vpn_shop\bot.py root@192.0.2.1:/root/vpn-shop/vpn_shop/bot.py
scp -o BindAddress=192.168.1.100 .\subjson-service\app.py root@192.0.2.1:/root/subjson-service/app.py
```

Проверка и рестарт:

```bash
cd /root/vpn-shop
python3 -m compileall vpn_shop

cd /root/subjson-service
python3 -m py_compile app.py

systemctl restart subjson.service
systemctl restart vpn-shop-silentconnect.service
systemctl is-active subjson.service vpn-shop-silentconnect.service
```

## 17. Восстановление После Неудачного Деплоя

1. Найти последний бэкап:

```bash
ls -la /root/deploy-backups
```

2. Вернуть файлы:

```bash
cp /root/deploy-backups/<ts>/bot.py /root/vpn-shop/vpn_shop/bot.py
cp /root/deploy-backups/<ts>/subjson-app.py /root/subjson-service/app.py
```

3. Проверить компиляцию и перезапустить сервисы:

```bash
cd /root/vpn-shop && python3 -m compileall vpn_shop
cd /root/subjson-service && python3 -m py_compile app.py
systemctl restart subjson.service vpn-shop-silentconnect.service
```

4. Проверить логи:

```bash
journalctl -u vpn-shop-silentconnect.service -n 100 --no-pager
journalctl -u subjson.service -n 100 --no-pager
```

## 18. Проверочный Чеклист После Изменений

Минимум после каждого деплоя:

- `systemctl is-active` показывает `active` для бота и subjson;
- `python3 -m compileall vpn_shop` проходит без ошибок;
- `python3 -m py_compile app.py` проходит без ошибок;
- `/healthz` у `subjson-service` отвечает `{"ok": true}`;
- бот открывает меню;
- админка открывается;
- тестовый профиль создаётся;
- общая страница подключения открывается;
- кнопка `Подключить` ведёт на `/import/<subscription_id>`;
- внутренние переходы Happ/Streisand/V2RayTun не ведут на 404.

После крупных изменений дополнительно:

- пробник создаётся один раз;
- повторный пробник блокируется;
- платный заказ создаётся;
- `Оплачено` отправляет уведомление админу;
- подтверждение оплаты создаёт профиль;
- продление продлевает старый профиль, а не создаёт новый;
- реферальное начисление появляется только после платной оплаты;
- заказ с `final_price_rub = 0` не даёт реферальную комиссию;
- лимит устройств в x-ui соответствует выбранному тарифу.

## 19. Что Считать Готовым

На текущий момент система уже закрывает основные задачи:

- открытый вход по ссылке;
- ручные оплаты;
- уведомление об оплате;
- админское подтверждение;
- автоматическая выдача подписки;
- импорт в популярные приложения;
- пробник;
- продления;
- рефералка;
- базовая юридическая защита;
- RU-direct маршрутизация;
- лимиты одновременных устройств.

То есть это уже не черновик, а рабочий MVP, который можно осторожно давать пользователям.

## 20. Остаточные Риски И Что Улучшить Позже

Главные технические ограничения:

- `limitIp` ограничивает IP, а не железные устройства;
- ручная оплата требует дисциплины админа;
- нет веб-панели аналитики, всё через Telegram и SQLite;
- нет регулярного автоматического offsite-бэкапа;
- нет полноценного мониторинга latency/packet loss;
- legal-текст не проверен профильным юристом;
- Hiddify не поддерживаем как целевое приложение;
- нагрузочное тестирование на 50-100 реальных пользователей ещё не проводилось.

Хорошие следующие шаги:

- настроить ежедневный бэкап SQLite и env-файлов в отдельное место;
- добавить простой мониторинг `x-ui`, `subjson`, `bot`, CPU/RAM/disk;
- сделать команду или админ-кнопку для просмотра активных подписок;
- сделать отдельную внутреннюю инструкцию для поддержки пользователей;
- протестировать гибридный `TCP+XHTTP` на 2-3 людях;
- решить, нужно ли массово перевести старые активные профили на лимит 3/6/9.
