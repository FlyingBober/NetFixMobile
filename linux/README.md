# NetFix Linux Headless

Консольный Linux-клиент из проекта **NetFix** с двумя независимыми `systemd`-сервисами:

- **`netfix-dpi.service`** — системный обход DPI без TUN/VPN:
  - основной движок **`nfqws`** (`bol-van/zapret`, ядерный `NFQUEUE` + `nftables`/`iptables`);
  - альтернативный движок **`ciadpi`** (`hufrea/byedpi`, режим локального `socks5` или `transparent` redirect).
- **`netfix-tgproxy.service`** — локальный MTProto-over-WebSocket прокси для Telegram (`native/tgproxy-rust`) с поддержкой Cloudflare CDN fallback/priority, работающий от непривилегированного пользователя `netfix`.
- **`netfixctl`** — единая CLI-утилита управления сервисами, автоподбором стратегий (`scan`), проверкой Telegram DC/Cloudflare (`dc-check`), переключением DNS, управлением `/etc/hosts`, установкой и удалением. Все управляющие и диагностические команды поддерживают `--json` для последующей интеграции с GUI/треем.

---

## Требования

- Linux с `systemd` и `nftables` (`nft`) или `iptables`/`ip6tables`.
- Для сборки из исходников: `cargo`/`rustc` (Rust 2021) или Docker-образ `netfix-rust-ci:latest`.
- Для автоматического скачивания движков `nfqws` и `ciadpi` при `setup`: доступ к GitHub Releases (либо передайте локальную папку через `--from-local <dir>`).

---

## Быстрая установка

Из корня репозитория:

```bash
./linux/install.sh --enable --start
```

Скрипт сам:
1. Соберёт релизные бинарники `netfixctl` и `netfix-tgproxy` (`cargo` или Docker `netfix-rust-ci:latest`).
2. Установит их в `/usr/local/bin/`.
3. Выполнит `sudo netfixctl setup` (создаст пользователя `netfix`, каталоги `/etc/netfix`, `/var/lib/netfix/tgproxy`, `/usr/local/libexec/netfix`, установит `systemd`-юниты, дефолтный `config.toml`, список хостов и движки `nfqws`/`ciadpi`).
4. При флагах `--enable` и `--start` сразу включит автозапуск и запустит оба сервиса.

Полезные опции `./linux/install.sh`:
- `--from-local <dir>` — взять `nfqws`/`ciadpi` из локальной папки вместо скачивания с GitHub;
- `--skip-download` — не скачивать движки (если они уже в `PATH` или `/usr/local/libexec/netfix`);
- `--no-build` — установить уже собранные бинарники из `linux/target/release/`;
- `--bin-dir <dir>` — изменить каталог установки бинарников (по умолчанию `/usr/local/bin`).

---

## Быстрый старт после установки

```bash
# 1. Автоподбор лучшей DPI-стратегии (YouTube + Discord + потоковый чанк) и сохранение в config.toml
sudo netfixctl scan --engine nfqws --apply

# 2. Запуск и включение автозапуска при загрузке ОС
sudo netfixctl enable all
sudo netfixctl start all

# 3. Получение ссылки/QR-кода для Telegram (MTProto dd-прокси 127.0.0.1:1443)
sudo netfixctl tg link
sudo netfixctl tg qr

# 4. Проверка состояния сервисов и доступности Telegram DC / CF-доменов
sudo netfixctl status
sudo netfixctl dc-check
```

---

## Основные команды `netfixctl`

Глобальные флаги:
- `--config <PATH>` — путь к конфигу (по умолчанию `$NETFIX_CONFIG` или `/etc/netfix/config.toml`);
- `--json` — вывод результата и ошибок в формате JSON.

| Команда | Назначение |
| --- | --- |
| `netfixctl setup [--from-local <dir>] [--skip-download]` | Первичная настройка, юниты `systemd`, пользователь `netfix`, установка `nfqws`/`ciadpi` |
| `netfixctl start\|stop\|restart [all\|dpi\|tg]` | Управление сервисами `netfix-dpi.service` и `netfix-tgproxy.service` |
| `netfixctl enable\|disable [all\|dpi\|tg]` | Включение/отключение автозапуска сервисов при старте системы |
| `netfixctl status [all\|dpi\|tg]` | Состояние юнитов, активный движок/стратегия, параметры TG-прокси, профиль сети и DNS |
| `netfixctl network [current\|list\|switch <profile\|auto>]` | Просмотр текущей сети, списка сохранённых профилей и переключение активного профиля |
| `netfixctl scan [--engine nfqws\|ciadpi] [--no-discord] [--ech] [--apply]` | Двухфазный автоподбор стратегии обхода DPI и сохранение под текущую сеть |
| `netfixctl dc-check` | Проверка прямых `DC1–DC5` и пула Cloudflare-доменов для Telegram |
| `netfixctl tg link\|qr\|pin-cf <domain\|auto>` | Ссылка `tg://proxy`, QR-код в терминале и закрепление CF-домена |
| `netfixctl dns [status\|set <mode> [servers...]\|reset]` | Просмотр, смена и откат системного DNS (`system`, `cloudflare`, `google`, `quad9`, `adguard`, `custom`) |
| `netfixctl hosts [status\|apply <file>\|reset]` | Управление блоком `# BEGIN NETFIX MANAGED` в `/etc/hosts` с бэкапом |
| `netfixctl uninstall [--purge]` | Удаление `systemd`-юнитов и движков (с `--purge` также удаляет конфиг/стейт и откатывает DNS/`hosts`) |

---

## Где всё настраивается

### 1. Основной конфиг: `/etc/netfix/config.toml`
Права `0640` (`root:netfix`). После ручного редактирования перезапустите нужный сервис (`sudo netfixctl restart dpi` или `sudo netfixctl restart tg`).

- **`[general]`**
  - `log_level` — `"info"` или `"debug"` (включает подробные логи в `journalctl -u netfix-tgproxy`).
  - `active_network_override` — принудительное имя сетевого профиля (иначе определяется автоматически по Wi-Fi SSID или интерфейсу маршрута по умолчанию).
- **`[dpi]`**
  - `enabled` — включение DPI-обхода.
  - `engine` — `"nfqws"` (по умолчанию) или `"ciadpi"`.
  - `ciadpi_mode` — `"socks5"` (слушает `socks_bind:socks_port`) или `"transparent"` (`transparent_port` + перенаправление через firewall).
  - `nfqueue_num` (`200`), `fwmark` (`1073741824` = `0x40000000`), `game_filter` (`false` — TCP 80/443 + UDP 443; `true` — также UDP 1024–65535).
  - `ipset_mode` — `"any"` (все целевые порты), `"loaded"` (только заданные `ipset_v4`/`ipset_v6`) или `"none"`.
  - `hostlist_path` — путь к списку доменов для `nfqws` (если не задан, используется `/etc/netfix/hostlists/default.txt`).
  - `active_strategy_nfqws`, `active_strategy_ciadpi` и `[dpi.network_strategies.<profile>]` — активная и сохранённые по сетям стратегии.
- **`[tgproxy]`**
  - `bind_ip` (`127.0.0.1`), `port` (`1443`), `secret` (32 hex-символа без `dd`).
  - `cf_enabled` (`true`) — туннелирование через Cloudflare.
  - `cf_priority` (`true`) — приоритетное использование Cloudflare для всех DC (при `false` сначала пробуются прямые адреса из `dc_ips`).
  - `cf_plain_first` — сначала пробовать WS по HTTP `:80`, затем TLS `:443`.
  - `pinned_cf_domain` — закреплённый домен CF (`""` = автовыбор).
  - `dc_ips` — прямые IP дата-центров (например, `"2:149.154.167.220,4:149.154.167.220"`).
  - `tls_verify` (`true`), `pool_size` (`4`), `cache_dir` (`/var/lib/netfix/tgproxy`).
- **`[dns]`**
  - `mode` — `"system"`, `"cloudflare"`, `"google"`, `"quad9"`, `"adguard"`, `"custom"`.
  - `custom_servers` — список IP для режима `"custom"`.

### 2. DNS (`netfixctl dns`)
Режим DNS задаётся командой `sudo netfixctl dns set <mode>` (и отражается в секции `[dns]` файла `/etc/netfix/config.toml`). В зависимости от системы NetFix автоматически выбирает бэкенд:
- **`systemd-resolved`** (основной): создаёт `/etc/systemd/resolved.conf.d/90-netfix.conf` (`DNS=...` с SNI-именем для встроенных провайдеров, `Domains=~.` и `DNSOverTLS=opportunistic`, не ломающий локальные/VPN-серверы и смены сетей). При этом профили NetworkManager и настройки в GNOME не затрагиваются, соединение не обрывается, а перезапуск `systemd-resolved` подхватывает новые параметры мгновенно.
- **`NetworkManager` (если `systemd-resolved` отключён)**: обновляет `ipv4.dns`/`ipv6.dns` через `nmcli` с сохранением бэкапа в `/var/lib/netfix/dns-nmcli-backup.json`.
- **Прямой `/etc/resolv.conf`**: сохраняет оригинал в `/var/lib/netfix/resolv.conf.bak` и записывает новые `nameserver`.

Вернуть исходные настройки:
```bash
sudo netfixctl dns reset
```

### 3. `/etc/hosts` и списки доменов
- Управляемый блок в `/etc/hosts` ограничен маркерами `# BEGIN NETFIX MANAGED` / `# END NETFIX MANAGED` (оригинал сохраняется в `/var/lib/netfix/hosts.bak`).
- Пользовательский список доменов для `nfqws`: `/etc/netfix/hostlists/default.txt` (редактируется напрямую или через `hostlist_path` в `config.toml`).

### 4. Файлы сервисов и логи
- Юниты `systemd`: `/etc/systemd/system/netfix-dpi.service`, `/etc/systemd/system/netfix-tgproxy.service`, `/etc/systemd/system/netfix.target`.
- Диспетчер NetworkManager: `/etc/NetworkManager/dispatcher.d/90-netfix.sh` (автоматически перезапускает `netfix-dpi.service` при переключении Wi-Fi или проводных интерфейсов, подхватывая сохранённую для текущей сети стратегию).
- Движки DPI: `/usr/local/libexec/netfix/nfqws`, `/usr/local/libexec/netfix/ciadpi`.
- Просмотр логов:
  ```bash
  sudo journalctl -u netfix-dpi.service -f
  sudo journalctl -u netfix-tgproxy.service -f
  ```

### 5. Сетевые профили (`netfixctl network`)
- Просмотр текущей распознанной сети и активной стратегии:
  ```bash
  netfixctl network current
  ```
- Список сохранённых профилей:
  ```bash
  netfixctl network list
  ```
- Принудительное переключение или возврат в авто-режим:
  ```bash
  sudo netfixctl network switch home_wifi
  sudo netfixctl network switch auto
  ```

---

## Коды возврата `netfixctl`

- `0` — успех;
- `1` — ошибка выполнения / сети / `systemd`;
- `2` — неверные аргументы CLI или ошибка валидации `config.toml`;
- `3` — недостаточно прав (требуется `sudo`/`root`);
- `4` — не найден бинарник движка (`nfqws`/`ciadpi`).

---

## Удаление

Удалить `systemd`-юниты, движки и бинарники из `/usr/local/bin/` (с сохранением `/etc/netfix/config.toml`):

```bash
./linux/uninstall.sh
```

Полное удаление с очисткой `/etc/netfix`, `/var/lib/netfix`, откатом DNS и `/etc/hosts`, и удалением системного пользователя `netfix`:

```bash
./linux/uninstall.sh --purge
```
