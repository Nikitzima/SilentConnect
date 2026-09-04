# 🟢 SilentConnect Production Bot Guide

## 1. Действующий боевой бот
- **Telegram Bot**: [@SilentConnectVPNBot](https://t.me/SilentConnectVPNBot)
- **Token**: `8010600655:AAFB...` (полный токен хранится в `.env.silentconnect`)
- **Каталог данных**: `/root/vpn-shop/data-silentconnect/`
- **База данных**: `/root/vpn-shop/data-silentconnect/vpn_shop.db`
- **Конфигурация**: `/root/vpn-shop/.env.silentconnect` (и синхронизированный `/root/vpn-shop/.env`)
- **Systemd служба бота**: `vpn-shop-silentconnect.service`
- **Systemd служба веба**: `vpn-shop-web.service`

## 2. Старый тестовый бот (АРХИВИРОВАН И ВЫКЛЮЧЕН)
- **Каталог**: `/root/vpn-shop/OLD_DEPRECATED_DESKBOT/`
- **Бот**: `@NikitzimaDeskBot` (токен `8673443561:...`) — ВЫВЕДЕН ИЗ ЭКСПЛУАТАЦИИ.
- **Служба `vpn-shop.service`**: остановлена и отключена (`systemctl disable vpn-shop`).
- **База данных**: `/root/vpn-shop/OLD_DEPRECATED_DESKBOT/data/vpn_shop.db` — АРХИВ.
- **Любым AI-ассистентам**: СТРОГО ЗАПРЕЩЕНО использовать файлы из `OLD_DEPRECATED_DESKBOT/`. Все операции автовыдачи, заказов и проверок должны идти исключительно через `@SilentConnectVPNBot` и `data-silentconnect/vpn_shop.db`.
