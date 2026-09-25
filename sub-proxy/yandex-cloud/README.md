# SilentConnect Yandex Cloud Serverless Edge Proxy

## Архитектура и Назначение

Serverless отказоустойчивый прокси на базе **Yandex Cloud Serverless Ecosystem** (Cloud Functions + API Gateway + Certificate Manager).

Прокси решает критические задачи доступности инфраструктуры SilentConnect для пользователей из РФ и стран СНГ:
1. **Обход блокировок и замедлений магистральных провайдеров**: прямое обращение из РФ к европейским серверам (NL, PL) может блокироваться ТСПУ/провайдерами по IP или SNI. Серверы Yandex Cloud имеют прямые высокоскоростные каналы связи как с российскими сетями, так и с европейскими дата-центрами.
2. **Мгновенный автоматический Failover (NL ➔ PL ➔ FI)**:
   - Если основной сервер (NL) недоступен или не отвечает в течение 3.5 секунд, запрос автоматически и прозрачно для пользователя перенаправляется на резервный сервер (PL), а затем на финский узел (FI).
3. **Бесшовное продление и оплата**:
   - Страница личного кабинета (`sub.<domain>.net`), витрина и оформление заказа (`<domain>.net/order/...`), а также вебхуки эквайринга Platega (`POST /api/payment/platega/callback`) обслуживаются синхронно через один и тот же отказоустойчивый шлюз.
4. **Нулевая стоимость обслуживания (Zero Cost)**:
   - Прокси работает полностью в рамках постоянного бесплатного лимита Yandex Cloud (Free Tier: 1 000 000 вызовов функций в месяц).
   - В облаке **не создаются** платные виртуальные машины Compute Cloud или сетевые диски.

---

## Топология маршрутизации

```mermaid
flowchart TD
    User["Пользователь (Браузер / Приложение / Platega)"]
    CF["Cloudflare DNS (DNS-Only ⚪, CNAME Flattening)"]
    YCGW["YC API Gateway (sub-proxy-gateway)\nAnycast Edge IP"]
    YCFunc["YC Serverless Function (sub-proxy, Node.js 22)\n256 MB, 5s timeout"]
    
    NL["🇳🇱 Primary Node (NL)\nUpstream Origin:4430"]
    PL["🇵🇱 Standby Node (PL)\nUpstream Origin:4430"]
    FI["🇫🇮 Standby Node (FI)\nUpstream Origin:4430"]

    User -->|HTTPS| CF
    CF -->|Anycast IP| YCGW
    YCGW --> YCFunc
    
    YCFunc -->|1. Попытка (timeout 3.5s)| NL
    NL -.->|Сбой / Таймаут| PL
    YCFunc -->|2. Резерв при сбое NL| PL
    PL -.->|Сбой / Таймаут| FI
    YCFunc -->|3. Аварийный резерв| FI
```

---

## Правила кэширования и изоляции

1. **Host-Aware Isolation**: Ключ кэша изолирован по домену источника:
   `cacheKey = ${incomingHost}:${httpMethod}:${fullPath}`
2. **Запрет кэширования для чувствительных путей**:
   - `/order/*` — страницы заказов и чеков
   - `/api/*` — платежные колбэки, вебхуки, внутренние API
   - `/cabinet/*` — личный кабинет по email
   - `/auth/*` — токены и сессии авторизации
   - `/renew` — создание заказов продления
3. **Микрокэш статики (5 сек)**: Для снижения нагрузки при пиковых всплесках обновлений подписок приложениями Happ / Sing-box / Streisand.
4. **Аварийный Stub**: Если все апстримы недоступны, прокси возвращает валидный JSON-конфиг для клиентов с сервисным сообщением «Серверы на плановом обновлении», предотвращая удаление профилей пользователями.

---

## Инструкция по развертыванию

1. Упаковать код функции в архив:
   ```bash
   zip -r sub_proxy.zip index.js package.json
   ```
2. Создать или обновить версию функции в YC:
   ```bash
   yc serverless function version create \
     --function-name sub-proxy \
     --runtime nodejs22 \
     --entrypoint index.handler \
     --memory 256m \
     --execution-timeout 5s \
     --source-path sub_proxy.zip
   ```
3. Привязать домены и сертификаты в API Gateway:
   ```bash
   yc serverless api-gateway add-domain sub-proxy-gateway --domain <domain>.net --certificate-id <CERT_ID_APEX>
   yc serverless api-gateway add-domain sub-proxy-gateway --domain www.<domain>.net --certificate-id <CERT_ID_WWW>
   yc serverless api-gateway add-domain sub-proxy-gateway --domain sub.<domain>.net --certificate-id <CERT_ID_SUB>
   ```
