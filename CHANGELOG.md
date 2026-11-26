# Changelog

Все заметные изменения в Linux-клиенте **NetFixLinux** (CLI, демоны и GUI) фиксируются в этом файле.

## [1.4.0] — 2026-11-26

### Исправления
- **Telegram Proxy (`netfixlinux-gui`):** исправлена ошибка, из-за которой GUI без прав root возвращал захардкоженный тестовый секрет вместо реального секрета из `/etc/netfix/config.toml`, что приводило к ошибке `неверное рукопожатие` в `netfix-tgproxy`. Теперь ссылка запрашивается через Polkit (`pkexec --disable-internal-agent netfixctl tg link`) и при отсутствии доступа возвращает явную ошибку.

### Новые возможности
- **Управление Cloudflare Fronting (CLI + GUI):**
  - В `netfixctl` добавлена команда `netfixctl tg cf` (`--enabled`, `--priority`, `--plain-first`, `--pin-domain`, `--front-ips`).
  - В `netfixctl --json status` добавлены поля `cf_priority`, `cf_plain_first` и `cf_front_ips`.
  - В GUI в карточке **Telegram Proxy** добавлена кнопка **Настроить** с модальным окном управления параметрами Cloudflare Fronting и автоматическим перезапуском `netfix-tgproxy.service`.
- **Версия в главном окне при релизе:** версия приложения теперь пробрасывается при сборке через `NETFIX_APP_VERSION` (в CI из тега релиза) и динамически отображается в заголовке окна, сайдбаре и `get_app_info`.

---

## [1.3.0] — 2026-11-25

### Изменения
- **Разделение пакетов:**
  - `netfixlinux` — полный пакет all-in-one (GUI + CLI + systemd-демоны + встроенные движки `nfqws`/`ciadpi`).
  - `netfixlinux-core` — headless-пакет без GUI (только CLI + systemd-демоны + встроенные движки).
- **Установщик и провижининг:** добавлен флаг `netfixctl setup --skip-units` и автоматическое определение каталога бинарников (`/usr/bin` vs `/usr/local/bin`) при генерации systemd-юнитов.
- **Сборка:** обновлены `package.sh`, `fetch-engines.py`, `install.sh` и `uninstall.sh` для пакетного развёртывания «из коробки».

---

## [1.2.0] — 2026-11-25

### Новые возможности
- **Desktop GUI (`netfixlinux-gui`):** добавлен графический клиент на Tauri v2 (управление DPI и Telegram Proxy, автоподбор стратегий, DNS-пресеты, системный трей, Polkit, автозапуск).
- **CLI:** добавлена подкоманда `netfixctl apply` и расширен список хостов Discord.

### Исправления
- **Стабильность (`netfix-core`):** добавлен retry при временной ошибке `ETXTBSY` в `DpiRunner::spawn_command`.

---

## [1.1.1] — 2026-11-20

### Оптимизации и исправления
- **Telegram Proxy (`netfix-tgproxy`):** детальные логи по соединениям и idle-статистика перенесены на уровень `debug`.
- **CI/CD:** исправлена кросс-сборка RPM-пакетов для `aarch64` на x86_64-раннерах (`--target`).

---

## [1.1.0] — 2026-11-19

### Новые возможности
- Добавлены скрипт упаковки `package.sh` (`.tar.gz`, `.deb`, `.rpm`) и GitHub Actions workflows для CI и публикации релизов.
- Реализованы network-aware переключение стратегий, команды жизненного цикла и универсальная настройка DNS (`systemd-resolved` / `NetworkManager`).
