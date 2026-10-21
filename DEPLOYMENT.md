# Руководство по развёртыванию и восстановлению узлов SilentConnect (Active-Active Mesh)

> **Статус документа**: Актуальная боевая спецификация (Production Verified)  
> **Дата последней верификации**: 21.10.2026  
> **Целевая операционная система**: **Debian GNU/Linux 13 (Trixie)** / **Ubuntu 24.04 LTS** (ядро Linux 6.12+)  
> **Связанные документы**: [ARCHITECTURE.md](ARCHITECTURE.md) • [README.md](README.md) • [AMNEZIA_SLOTS.md](AMNEZIA_SLOTS.md) • [WHITELIST_SPEC.md](WHITELIST_SPEC.md)

---

## 1. Стандарт операционной системы и аппаратные требования

В архитектуре **Active-Active Mesh** все узлы кластера (**NL**, **PL**, **FI**) являются равноправными боевыми серверами. Базовым стандартом для развёртывания новых узлов утверждён дистрибутив **Debian GNU/Linux 13 (Trixie)** (либо **Ubuntu 24.04 LTS**) с ядром Linux 6.12+.

### Рекомендуемые характеристики узла:
- **CPU**: от 2 до 4 vCPU (обязательна аппаратная поддержка `AES-NI`).
- **RAM**: от 4 GB.
- **Диск**: NVMe от 40 GB (для хранения локальных реплик Turso `libSQL` со временем чтения `0.02 мс`).
- **Сеть**: 1–10 Gbps безлимитный канал, прямой публичный IPv4 без NAT провайдера.

---

## 2. Пошаговое развёртывание нового Mesh-узла с нуля

### Шаг 1: Подготовка ОС, пакетов и сетевого стека BBR
```bash
apt-get update && apt-get dist-upgrade -y

apt-get install -y \
    curl wget git jq ufw rsync htop net-tools \
    build-essential python3 python3-pip python3-venv \
    sqlite3 libsqlite3-dev ca-certificates gnupg lsb-release \
    iptables iptables-persistent fail2ban rclone

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

### Шаг 2: Триангуляция идентификации узла (`node_code`)
> [!IMPORTANT]
> Подсистема `awg_manager.py` и реконсилятор `xui_reconciler.py` проверяют консистентность кода ноды по трём источникам: файлу `/etc/silentconnect/node_code`, переменной `AWG_LOCAL_SERVER` и системному `hostname`. При расхождении срабатывает защита `NodeIdentityConflictError`.

```bash
# Укажите код текущей ноды: nl, pl или fi
NODE_CODE="pl"

mkdir -p /etc/silentconnect
echo "${NODE_CODE}" > /etc/silentconnect/node_code
chmod 644 /etc/silentconnect/node_code
```

### Шаг 3: Установка Docker, 3X-UI, Caddy и Hysteria 2
```bash
# 1. Установка Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

# 2. Установка 3X-UI
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

# 3. Установка Caddy v2
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# 4. Установка Hysteria 2
bash <(curl -fsSL https://get.hy2.sh/)
```

### Шаг 4: Настройка Python-окружения и драйвера `libsql`
```bash
cd /root/vpn-shop
python3 -m venv venv
/root/vpn-shop/venv/bin/pip install --upgrade pip
/root/vpn-shop/venv/bin/pip install libsql cryptography qrcode pyyaml

# Инициализация локальной реплики Turso
/root/vpn-shop/venv/bin/python3 -m vpn_shop --env-file .env.silentconnect init-db
```

---

## 3. Каталог и конфигурация Systemd-сервисов

В архитектуре Active-Active на каждом узле работают:
1. `subjson.service` — выдача подписок и мастер подключения (`:3088`).
2. `vpn-shop-web.service` — веб-витрина, личный кабинет и вебхуки (`:3090`).
3. `vpn-shop-xui-reconciler.service` — автономный демон Pull-реконсиляции 3X-UI и AmneziaWG из Turso.
4. `vpn-shop-silentconnect.service` — демон бота и периодических задач (координируется через `cluster_leases`).

### 3.1. Автономный реконсилятор: `/etc/systemd/system/vpn-shop-xui-reconciler.service`
```ini
[Unit]
Description=SilentConnect Autonomous 3X-UI & AWG Pull Reconciler (Turso Mesh)
After=network-online.target x-ui.service docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/root/vpn-shop/venv/bin/python3 -m vpn_shop --env-file .env.silentconnect reconcile-xui --daemon --interval 15.0
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3.2. Сервис подписок: `/etc/systemd/system/subjson.service`
```ini
[Unit]
Description=SilentConnect SubJSON Subscription Service
After=network.target x-ui.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/subjson-service
EnvironmentFile=/root/subjson-service/subjson.env
ExecStart=/root/vpn-shop/venv/bin/python3 /root/subjson-service/app.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3.3. Сервис веб-витрины и чекаута: `/etc/systemd/system/vpn-shop-web.service`
```ini
[Unit]
Description=SilentConnect VPN Shop Web Cabinet & Checkout
After=network-online.target x-ui.service subjson.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/root/vpn-shop/venv/bin/python3 -m vpn_shop --env-file .env.silentconnect run-web
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 3.4. Сервис бота и фоновых лизов: `/etc/systemd/system/vpn-shop-silentconnect.service`
> [!TIP]
> Благодаря таблице `cluster_leases` в Turso и автоматическому переключению в `SERVERLESS_MODE` при `HTTP 409 Conflict`, юнит `vpn-shop-silentconnect.service` безопасен при работе совместно с `tgcloud` и на нескольких нодах: фоновые задачи рассылки и очистки всегда выполняет ровно один узел, удерживающий активный лиз.

```ini
[Unit]
Description=VPN Shop Bot & Cluster Lease Worker - SilentConnect
After=network-online.target x-ui.service subjson.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/root/vpn-shop/venv/bin/python3 -m vpn_shop --env-file .env.silentconnect run-bot
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 3.5. SNI Мультиплексор порта 443: `/usr/local/etc/xray-multiplexer/config.json`
```json
{
  "log": { "loglevel": "warning", "access": "none" },
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
      "tag": "to-xray-reality",
      "settings": { "redirect": "127.0.0.1:23385" }
    },
    {
      "protocol": "freedom",
      "tag": "to-caddy-web",
      "settings": { "redirect": "127.0.0.1:4430" }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "domain": ["<REALITY_SNI_1>", "<REALITY_SNI_2>", "<REALITY_SNI_3>"],
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

### 3.6. Конфигурация Caddy: `/etc/caddy/Caddyfile`
```caddy
{
    https_port 4430
    http_port 80
    admin 127.0.0.1:2019
}

<PL_DOMAIN>, <SUB_DOMAIN>, <EDGE_DOMAIN>, <SHOP_DOMAIN>, www.<SHOP_DOMAIN> {
    @ws_inbound path /sc-ws-path*
    handle @ws_inbound {
        reverse_proxy 127.0.0.1:10010
    }

    @shop_routes {
        path / /order/* /api/* /cabinet/* /legal/* /about /contact /assets/telegram/*
    }
    handle @shop_routes {
        encode zstd gzip
        reverse_proxy 127.0.0.1:3090
    }

    handle {
        encode zstd gzip
        reverse_proxy 127.0.0.1:3088
    }
}
```

### 3.7. Конфигурация Hysteria 2: `/etc/hysteria/config.yaml`
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
```

---

## 4. Сетевая безопасность, UFW и правила Iptables

### 4.1. Настройка UFW и отключение шумного логирования
```bash
ufw default deny incoming
ufw default allow outgoing
ufw logging off

ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 4430/tcp
ufw allow 8443/tcp
ufw allow 23385/tcp
ufw allow 29443/tcp
ufw allow 38443/udp
ufw allow 44121/udp          # На узле FI: 49752/udp
ufw allow 30000:40000/udp    # Port Hopping для Hysteria 2

# Блокировка прямого внешнего доступа к внутренним портам
ufw deny 2053/tcp
ufw deny 2096/tcp
ufw deny 3088/tcp
ufw deny 3090/tcp

ufw --force enable
```

### 4.2. Редиректы портов Hysteria 2 и NAT AmneziaWG
```bash
iptables -t nat -A PREROUTING -p udp --dport 30000:40000 -j REDIRECT --to-ports 38443
iptables -t nat -A PREROUTING -p udp --dport 443 -j REDIRECT --to-ports 38443

iptables -t nat -A DOCKER ! -i docker0 -p udp --dport 44121 -j DNAT --to-destination 172.17.0.2:44121
iptables -t nat -A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p udp --dport 44121 -j MASQUERADE

netfilter-persistent save
```

---

## 5. Аварийное восстановление узла (Disaster Recovery)

В архитектуре Active-Active с **Turso (libSQL)** восстановление данных при полной замене сервера происходит автоматически:

1. **Восстановление системных конфигураций из Google Drive**:
   ```bash
   rclone copy gdrive:<GDRIVE_BACKUP_FOLDER_ID>/backup_pl/pl_stack_LATEST.tar.gz /var/tmp/
   cd /var/tmp && tar -xzvf pl_stack_LATEST.tar.gz
   cp -f etc/x-ui/x-ui.db /etc/x-ui/x-ui.db
   cp -f etc/caddy/Caddyfile /etc/caddy/Caddyfile
   cp -f etc/hysteria/config.yaml /etc/hysteria/config.yaml
   ```
2. **Автоматическое стягивание БД и клиентов из Turso**:
   При запуске `vpn-shop-xui-reconciler.service` узел автоматически:
   - Скачивает актуальную реплику `vpn_shop` из облака Turso на NVMe.
   - Догоняет все новые/продлённые профили в локальную панель `3X-UI` через REST API.
   - Генерирует и применяет актуальный `/opt/amnezia/awg/awg0.conf` со всеми активными слотами AmneziaWG для данной локации.

---

## 6. Чеклист валидации после развёртывания (Post-Deployment Checklist)

| № | Проверка | Команда терминала | Ожидаемый результат |
|---|---|---|---|
| **1** | Идентификация ноды | `cat /etc/silentconnect/node_code` | Выводит точный код узла (`nl`, `pl` или `fi`) |
| **2** | Службы Systemd | `systemctl is-active subjson vpn-shop-web vpn-shop-xui-reconciler x-ui caddy hysteria-server` | Все службы в статусе `active` |
| **3** | Реплика Turso | `ls -lh /root/vpn-shop/data-silentconnect/vpn_shop_replica_*.db` | Присутствуют файлы локальных реплик `web`, `subjson`, `xui_reconcile` |
| **4** | Тест реконсилятора | `python3 -m vpn_shop --env-file .env.silentconnect reconcile-xui --once --dry-run` | Возвращает JSON `{"ok": true, "profiles_checked": N, ...}` |
| **5** | Сокеты TCP/UDP | `ss -tulpn \| grep -E '443\|4430\|23385\|3088\|3090\|38443\|44121'` | Все порты прослушиваются штатными демонами |
| **6** | Hysteria 2 Auth | `curl -s -X POST http://127.0.0.1:3088/internal/hysteria-auth -d '{"auth":"test"}'` | Возвращает валидный JSON-ответ от `subjson` |
| **7** | Healthcheck Web | `curl -s http://127.0.0.1:3090/healthz` | `{"status":"ok"}` |
| **8** | Тихий режим логов | `grep -F '"access": "none"' /usr/local/x-ui/bin/config.json` | Логирование пользовательских подключений отключено |
