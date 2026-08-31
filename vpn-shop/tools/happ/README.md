# Happ Windows Golden Settings

Цель: раздавать пользователям Happ так, чтобы на Windows работал именно `Happ TUN` без самозаворота трафика в сам туннель.

## Что можно раздавать ссылкой

Happ поддерживает импорт конфигураций и подписок через deep link:

- `happ://crypto...` - зашифрованная подписка Happ.
- обычная HTTPS-ссылка на подписку.
- одиночные конфиги `vless://`, `vmess://`, `trojan://`, `ss://`, `socks://`.

Это импортирует серверы/подписку, но не чинит локальную маршрутизацию Windows. Для `Happ TUN` нужен отдельный Windows-route до IP VPN-сервера через физический шлюз.

## Золотые настройки Happ

Скрипт `setup-happ-tun.ps1` выставляет:

- `TUN`: включен.
- `Provider TUN`: `Happ TUN`.
- `System proxy`: выключен.
- `DNS from JSON`: включен.
- `Server resolving`: включен.
- DNS для TUN и resolver: `1.1.1.1` / `cloudflare-dns.com`.
- Sniffing/packet analysis: включен.
- Per-app proxy: выключен.
- Fragmentation: выключен.
- Autostart: включен по умолчанию.
- Windows persistent route `/32` до каждого server IP через физический gateway.

## Быстрый запуск на Windows

Для клиентов SilentConnect можно раздавать два файла из этой папки:

```text
SilentConnect-Happ-Fix.bat
setup-happ-tun.ps1
```

Пользователь запускает `SilentConnect-Happ-Fix.bat` обычным двойным кликом. Скрипт сделает бэкап HKCU-настроек Happ на рабочий стол, выставит рабочие TUN-настройки, добавит route до `192.0.2.1` и перезапустит Happ. Windows может показать UAC-запрос для добавления постоянного маршрута.

Для другого VPN-сервера используй универсальную обёртку:

```text
Happ-TUN-Fix-Universal.bat
setup-happ-tun.ps1
```

Она спросит домен или IP сервера при запуске. Можно также передать target первым аргументом:

```bat
Happ-TUN-Fix-Universal.bat edge.example.com
```

Открыть PowerShell в папке со скриптом:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-happ-tun.ps1 -ServerTargets "192.0.2.1"
```

Для нескольких серверов:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-happ-tun.ps1 -ServerTargets "192.0.2.1","server2.example.com"
```

С импортом подписки:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-happ-tun.ps1 `
  -ServerTargets "192.0.2.1" `
  -HappLink "happ://crypto..." `
  -BackupSettings `
  -RestartHapp `
  -OpenHappLink
```

Скрипт сам определяет физический IPv4 gateway, просит UAC только для маршрутов и делает route постоянным через `route -p`.

## Проверка

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\setup-happ-tun.ps1 -VerifyOnly
```

Правильный результат: маршрут до server IP идет через `Ethernet`/Wi-Fi и обычный LAN IP, например `192.168.1.100`, а не через `10.6.7.1` или другой TUN IP.

## Личная резервная копия

Для своего ПК можно отдельно сохранить локальные данные Happ:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\export-happ-settings.ps1
```

Если нужно сохранить и локальную базу подписок для собственного ПК:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\export-happ-settings.ps1 -IncludeSubscriptionsDb
```

`subs.db` лучше не распространять клиентам: там может быть локальная база подписок/серверов. Для клиентов используй подписочную ссылку `happ://crypto...` или HTTPS.

## Ограничение

Если IP VPN-сервера меняется, route нужно обновить. Для домена можно передавать домен в `-ServerTargets`: скрипт резолвит A-записи и добавляет routes к текущим IP.

Официальная документация Happ:

- https://www.happ.su/main/faq/adding-configuration-subscription
- https://www.happ.su/main/faq/share-configuration
- https://docs.happ-proxy.com/getting-started/api
