# Руководство по развёртыванию и восстановлению узлов SilentConnect

> **Статус документа**: Актуальная боевая спецификация (Production Verified)  
> **Дата последней верификации**: 14.10.2026  
> **Целевая операционная система**: **Debian GNU/Linux 13 (Trixie)** (ядро Linux 6.12+)  
> **Связанные документы**: [ARCHITECTURE.md](ARCHITECTURE.md) • [README.md](README.md) • [WHITELIST_SPEC.md](WHITELIST_SPEC.md) • [AMNEZIA_SLOTS.md](AMNEZIA_SLOTS.md)

---

## 1. Стандарт операционной системы и аппаратные требования

Начиная с октября 2026 года в инфраструктуре SilentConnect утверждён переход на **Debian GNU/Linux 13 (Trixie)** в качестве единого базового дистрибутива (успешно введён в строй на узле PL Standby `<PL_IP>` с сетевым каналом 10 Gbps). Новые резервные узлы должны разворачиваться исключительно на Debian 13.

### Рекомендуемые характеристики сервера:
- **CPU**: от 2 до 4 vCPU (поддержка AES-NI обязательна).
- **RAM**: от 4 GB (минимум 2 GB для чистых Standby-нод).
- **Диск**: NVMe от 40 GB.
- **Сеть**: 1–10 Gbps безлимитный трафик. Прямой публичный IPv4 (без NAT провайдера).
- **Поддержка ядра**: Linux 6.12+ (встроенная поддержка современных сетевых планировщиков BBR, eBPF и расширенных модулей WireGuard).

---

## 2. Развёртывание нового Standby-узла с нуля (Step-by-Step)

### Шаг 1: Первичная подготовка ОС и базовые пакеты
```bash
# Обновление индекса репозиториев Debian 13 Trixie
apt-get update && apt-get dist-upgrade -y

# Установка системных утилит и зависимостей ядра
apt-get install -y \
    curl wget git jq ufw rsync htop net-tools \
    build-essential python3 python3-pip python3-venv \
    sqlite3 libsqlite3-dev ca-certificates gnupg lsb-release \
    iptables iptables-persistent fail2ban rclone

# Включение BBR congestion control
cat <<'EOF' > /etc/sysctl.d/99-silentconnect.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
EOF
sysctl --system
```

### Шаг 2: Установка Docker и Docker Compose
```bash
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
```

### Шаг 3: Установка 3X-UI и ядра Xray
```bash
# Установка официального 3X-UI (поддерживающего XHTTP и Reality 0.0.0)
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

# Остановка сервиса для инициализации первичных каталогов
systemctl stop x-ui
```

### Шаг 4: Установка веб-сервера Caddy
```bash
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy
```

### Шаг 5: Установка Hysteria 2
```bash
bash <(curl -fsSL https://get.hy2.sh/)
systemctl stop hysteria-server
```

---

## 3. Каталог и конфигурация Systemd-сервисов

На резервном Standby-узле действуют строгие правила изоляции: **Telegram-бот отключён**, веб-витрина запущена в режиме Standby, подписки и прокси-инбаунды активны.

### 3.1. Сервис подписок: `/etc/systemd/system/subjson.service`
```ini
[Unit]
Description=SilentConnect SubJSON Subscription Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/subjson-service
EnvironmentFile=/root/subjson-service/subjson.env
ExecStart=/root/subjson-service/venv/bin/python3 -m uvicorn app:app --host 127.0.0.1 --port 3088 --workers 2
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3.2. Сервис веб-витрины: `/etc/systemd/system/vpn-shop-web.service`
```ini
[Unit]
Description=SilentConnect VPN Shop Web Cabinet & SBP Checkout
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/root/vpn-shop/venv/bin/python3 -m vpn_shop.web --port 3090
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3.3. Telegram-бот: `/etc/systemd/system/vpn-shop-silentconnect.service`
> **ВАЖНО**: На Standby-узлах этот юнит обязан быть **ОТКЛЮЧЁН**, чтобы избежать конкуренции за Telegram Long Polling / Webhook с NL Master!
```bash
systemctl disable --now vpn-shop-silentconnect.service
```

### 3.4. SNI Мультиплексор порта 443: `/etc/systemd/system/xray-multiplexer.service`
Бинарник Xray слушает сокет `0.0.0.0:443` и разделяет Reality SNI и Web SNI:
```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 4430,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "freedom",
      "tag": "to-xray-reality",
      "settings": {
        "redirect": "127.0.0.1:23385"
      }
    },
    {
      "protocol": "freedom",
      "tag": "to-caddy-web",
      "settings": {
        "redirect": "127.0.0.1:4430"
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "domain": [
          "<REALITY_SNI_1>", "<REALITY_SNI_2>", "<REALITY_SNI_3>"
        ],
        "outboundTag": "to-xray-reality"
      },
      {
        "type": "field",
        "network": "tcp",
        "outboundTag": "to-caddy-web"
      }
    ]
  }
}
```

### 3.5. Конфигурация Caddy: `/etc/caddy/Caddyfile`
```caddy
{
    https_port 4430
    admin 127.0.0.1:2019
}

# Прямой доступ по IP (резервный HTTP)
:80, :8080 {
    reverse_proxy 127.0.0.1:3088
}

# Основной шлюз доменов подписок и чекаута
<PL_DOMAIN>, <SUB_DOMAIN>, <EDGE_DOMAIN> {
    # WebSocket туннель VLESS 443
    @ws_inbound path /sc-ws-9c3d7f1e*
    handle @ws_inbound {
        reverse_proxy 127.0.0.1:10010
    }

    # API заказов и чекаут
    @shop_api path /order/* /api/payment/*
    handle @shop_api {
        reverse_proxy 127.0.0.1:3090
    }

    # Подписки и общие API
    handle {
        reverse_proxy 127.0.0.1:3088
    }
}
```

### 3.6. Конфигурация Hysteria 2: `/etc/hysteria/config.yaml`
```yaml
listen: :38443

obfs:
  type: gecko
  gecko:
    password: "<HYSTERIA_GECKO_PASSWORD>"
    min_packet_size: 64
    max_packet_size: 1400

auth:
  type: http
  http:
    url: http://127.0.0.1:3088/internal/hysteria-auth

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s

bandwidth:
  up: 1 Gbps
  down: 1 Gbps

ignoreClientBandwidth: false
disableUDP: false
```

---

## 4. Сетевая безопасность и правила Iptables

### 4.1. UFW Rate Limiting и блокировка внутренних портов
```bash
ufw default deny incoming
ufw default allow outgoing

# Защита SSH от перебора (hitcount 6 / 30s)
ufw limit 22/tcp

# Публичные порты веб-сервисов и мультиплексора
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 4430/tcp
ufw allow 8080/tcp

# Публичные порты протоколов туннелирования
ufw allow 8443/tcp     # XHTTP Reality
ufw allow 23385/tcp    # TCP Reality Vision
ufw allow 29443/tcp    # gRPC Reality
ufw allow 38443/udp    # Hysteria 2 UDP
ufw allow 44121/udp    # AmneziaWG (на FI: 49752/udp)
ufw allow 30000:40000/udp # Диапазон скачкообразных портов Hysteria

# Запрет доступа к внутренним портам извне
ufw deny 2053/tcp      # X-UI панель
ufw deny 2096/tcp      # X-UI панель доп.
ufw deny 3088/tcp      # SubJSON API
ufw deny 3090/tcp      # VPN Shop Web (доступен только через Caddy)

ufw --force enable
```

### 4.2. Настройка NAT PREROUTING и редиректов Hysteria 2
Добавьте в `/etc/iptables/rules.v4` (или выполните команды `iptables` с сохранением через `netfilter-persistent save`):

```bash
# Редирект UDP 443 и диапазона 30000:40000 на сокет Hysteria 38443
iptables -t nat -A PREROUTING -p udp --dport 30000:40000 -j REDIRECT --to-ports 38443
iptables -t nat -A PREROUTING -p udp --dport 443 -j REDIRECT --to-ports 38443

# Проброс AmneziaWG в Docker контейнер (IP amn0: 172.17.0.2)
iptables -t nat -A DOCKER ! -i docker0 -p udp --dport 44121 -j DNAT --to-destination 172.17.0.2:44121
iptables -t nat -A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p udp --dport 44121 -j MASQUERADE

# Сохранение правил
netfilter-persistent save
```

---

## 5. Восстановление узла из резервной копии (Disaster Recovery)

Бэкапы выгружаются в Google Drive через `rclone`. При выходе сервера из строя или необходимости ввода новой ноды процедура восстановления выглядит следующим образом:

### Шаг 1: Настройка rclone на целевом сервере
Создайте файл `/root/.config/rclone/rclone.conf` с валидным токеном Google Drive:
```ini
[gdrive]
type = drive
scope = drive
token = {"access_token":"<GDRIVE_ACCESS_TOKEN>","token_type":"Bearer","refresh_token":"<GDRIVE_REFRESH_TOKEN>"}
```

Проверьте доступность хранилища бэкапов:
```bash
rclone lsd gdrive:<GDRIVE_BACKUP_FOLDER_ID>/
# Ожидаемый вывод: backup_nl, backup_pl, backup_fi
```

### Шаг 2: Скачивание актуального Stack-архива
```bash
# Просмотр последних архивов
rclone ls gdrive:<GDRIVE_BACKUP_FOLDER_ID>/backup_pl/ | grep stack

# Загрузка последнего архива (например, pl_stack_2026-10-14_01-00-01.tar.gz)
rclone copy gdrive:<GDRIVE_BACKUP_FOLDER_ID>/backup_pl/pl_stack_LATEST.tar.gz /var/tmp/
```

### Шаг 3: Распаковка и развёртывание конфигураций
```bash
cd /var/tmp
tar -xzvf pl_stack_LATEST.tar.gz

# Восстановление базы X-UI
cp -f etc/x-ui/x-ui.db /etc/x-ui/x-ui.db
chmod 600 /etc/x-ui/x-ui.db

# Восстановление базы магазина
mkdir -p /root/vpn-shop/data-silentconnect
cp -f root/vpn-shop/data-silentconnect/vpn_shop.db /root/vpn-shop/data-silentconnect/vpn_shop.db

# Восстановление конфигураций Caddy, Hysteria, Xray
cp -rf etc/caddy/Caddyfile /etc/caddy/Caddyfile
cp -rf etc/hysteria/config.yaml /etc/hysteria/config.yaml
cp -rf usr/local/etc/xray-* /usr/local/etc/

# Перезапуск всех сервисов
systemctl restart x-ui caddy hysteria-server subjson vpn-shop-web
```

---

## 6. Чеклист валидации после развёртывания (Post-Deployment Checklist)

После завершения настройки выполните следующие команды для проверки корректности функционирования:

| Шаг проверки | Команда терминала | Ожидаемый результат |
|---|---|---|
| **1. Сокеты TCP** | `ss -tulpn \| grep -E '443\|4430\|8443\|23385\|3088\|3090'` | Все порты активны, 443 слушает Xray multiplexer, 4430 — Caddy |
| **2. Сокеты UDP** | `ss -tulpn \| grep -E '38443\|44121'` | 38443 занят hysteria, 44121 занят docker-proxy (AWG) |
| **3. Правила NAT** | `iptables -t nat -S \| grep REDIRECT` | Редиректы UDP 443 и 30000:40000 на 38443 присутствуют |
| **4. Статус служб** | `systemctl is-active subjson vpn-shop-web x-ui caddy hysteria-server` | Все службы возвращают `active` |
| **5. Проверка Standby**| `systemctl is-active vpn-shop-silentconnect` | Возвращает `inactive` (бот не должен работать на standby) |
| **6. База данных** | `sqlite3 -readonly /etc/x-ui/x-ui.db "SELECT count(*) FROM inbounds;"` | Число инбаундов >= 3 (Reality, XHTTP, gRPC) |
| **7. Hysteria Auth** | `curl -s http://127.0.0.1:3088/internal/hysteria-auth -d '{"user":"test"}'` | Возвращает корректный HTTP-ответ от SubJSON |
| **8. Web Checkout** | `curl -sI http://127.0.0.1:3090/healthz \| head -n 1` | `HTTP/1.1 200 OK` |
| **9. Приём бэкапа** | `ls -l --full-time /root/vpn-shop/data-silentconnect/vpn_shop.db` | Время обновления базы соответствует последнему 3-минутному циклу |
