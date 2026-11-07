# Тестирование ReviveGuard на реальном сервере (гайд)

Цель: проверить на настоящем Linux-сервере то, что тесты проверяют только на имитации, — прежде
всего SSH-исправления (`sshd -t`, `reload`, откат). **Не запускайте `fix` на боевом сервере.**

## 0. Подготовка (обязательно)

1. Одноразовый VPS: **Debian 12**, **Ubuntu 22.04** или **Ubuntu 24.04** (на Ubuntu 22.04 системный Python — 3.10,
   подходит — ReviveGuard поддерживает Python 3.10+).
2. Сделайте **снапшот** VPS в панели провайдера.
3. Убедитесь, что есть **консоль провайдера** (VNC / Rescue) — это ваш выход, если потеряете SSH.
4. Откройте **две** SSH-сессии. Вторую не закрывайте до конца тестов.
5. Создайте отдельного пользователя для проверок и дайте ему ключ:

```bash
sudo adduser --disabled-password --gecos "" rgtest
sudo usermod -aG sudo rgtest
```

## 1. Установка (одной командой)

Скрипт сам предупредит, что установит, и спросит подтверждение. Сначала прочитайте его:

```bash
apt-get update && apt-get install -y curl      # только если curl нет
curl -fsSLO https://raw.githubusercontent.com/JerryWenz/ReviveGuard/claude/quirky-franklin-vnj8hz/install.sh
less install.sh
bash install.sh
```

Он ставит недостающие `python3`, `python3-venv`, `ca-certificates`, создаёт `/opt/reviveguard/venv`,
делает команду `reviveguard` и запускает аудит (только чтение). Python 3.10 (Ubuntu 22.04) подходит.
Тесты репозитория на сервере запускать не обязательно.

Дальше команды вида `reviveguard ...` (от root, либо через `sudo`).

## 2. Аудит (только чтение)

```bash
reviveguard --lang ru audit            # без root: должно быть предупреждение
reviveguard --lang ru audit                                    # с root
reviveguard audit --format json > ~/audit.json
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods'
```

Проверьте: значения в отчёте совпадают с `sshd -T`; без root указан источник «parsed».

## 3. Сценарии SSH-исправлений

Каждый сценарий начинайте с проверки второй сессии и записывайте результат.

**A. Отказ без ключа (защита от lockout).** Пользователь `rgtest` без `authorized_keys`, вход
под ним по паролю:

```bash
reviveguard --lang ru fix --check SSH-002
```

Ожидание: «Требуется ручное исправление…», **файлы не изменены**
(`ls /etc/ssh/sshd_config.d/`).

**B. Успешное отключение паролей.** Добавьте ключ своему пользователю, проверьте вход по ключу
из **нового** окна, затем:

```bash
reviveguard fix --check SSH-002        # ответьте y, затем yes
sudo sshd -T | grep passwordauthentication       # ожидание: no
cat /etc/ssh/sshd_config.d/00-reviveguard-passwordauthentication.conf
```

Из третьего окна проверьте: вход по ключу работает; вход по паролю отклоняется.

**C. Откат.**

```bash
reviveguard history
reviveguard rollback                  # посмотрите план, подтвердите y
sudo systemctl reload ssh     # rollback сам службу не перезагружает
sudo sshd -T | grep passwordauthentication       # ожидание: снова yes
```

**D. Остальные SSH-исправления.** По очереди: `--check SSH-001`, `SSH-003`, `SSH-004`, `SSH-005`
(для SSH-003/004/005 сначала намеренно испортите настройку в `/etc/ssh/sshd_config.d/99-test.conf`
или права файла, затем исправьте и откатите).

**E. Повреждённая конфигурация.** Добавьте в `/etc/ssh/sshd_config.d/99-bad.conf` строку
`NoSuchOption yes` и запустите `fix --check SSH-003`. Ожидание: отказ «текущая конфигурация уже
некорректна». Удалите файл.

**F. Файрвол (только аудит).** `ufw` установлен, но выключен (`sudo ufw status`):
`reviveguard --lang ru audit` → ожидается находка `FW-001`. Затем **разрешите SSH-порт** и включите ufw
вручную (`sudo ufw allow 22/tcp && sudo ufw enable`; порт — ваш), повторите аудит: `FW-001..004` OK.
Откройте порт БД (`sudo ufw allow 3306/tcp`) → ожидается `FW-003`; удалите правило. Попробуйте
`reviveguard fix --category firewall`: ожидается «вручную», правила не меняются (`sudo ufw status` до/после).

**G. Fail2ban.** `sudo apt install -y fail2ban`; `reviveguard audit` (без root — пропуск). Чтобы вызвать
`F2B-002`, временно отключите jail: файл `/etc/fail2ban/jail.d/defaults-debian.conf` →
`enabled = false` для `[sshd]`, `sudo fail2ban-client reload`. Затем `reviveguard fix --check F2B-002`
(y), проверьте `sudo fail2ban-client status`, `sudo fail2ban-client status sshd`, откат
(`reviveguard rollback`) и `sudo fail2ban-client reload`. Верните `enabled` в исходное состояние.

**H. «Голый» сервер: обновления и недостающие пакеты.** По одному, после каждого шага смотрите
`reviveguard history` и повторяйте `reviveguard audit` (исправления открывают новые находки):

```bash
reviveguard fix --category updates      # UPD-001: обновить индекс apt (y)
reviveguard audit                       # теперь виден UPD-002/UPD-004
reviveguard fix --category updates      # UPD-002: только обновления безопасности (y, затем yes); UPD-004: автообновления
reviveguard fix --category fail2ban     # F2B-001: установка fail2ban, ваш IP попадёт в исключения
reviveguard fix --category firewall     # FW-001: установка ufw (остаётся ВЫКЛЮЧЕННЫМ)
reviveguard fix --category permissions  # права на файлы (если есть находки)
reviveguard fix --category sysctl       # безопасные параметры ядра (в контейнере будет пропуск)
```

Ожидание: пакетные операции в `history` помечены «не обратимо»; `rollback` для них отказывает;
после обновлений ядра `UPD-003` просит перезагрузку (сам ReviveGuard не перезагружает). Включение
ufw — только вручную: сначала `ufw allow 22/tcp`, потом `ufw enable`, из второй сессии.

## 4. Что прислать мне (без секретов)

- Вывод команд из пунктов 2–3 (текст в чат).
- `sudo sshd -T` целиком (ключей не содержит).
- `sudo journalctl -u ssh -n 50 --no-pager`
- `sudo ls -la /etc/ssh/sshd_config.d/` и `sudo cat /var/lib/reviveguard/history/*.json`
- Для F/G: `sudo ufw status verbose`, `sudo fail2ban-client status sshd`, вывод `audit`.
- Версию ОС: `cat /etc/os-release`, и `python3 --version`.

**Никогда не присылайте:** приватные ключи, содержимое `authorized_keys`, `/etc/shadow`, пароли,
токены. IP-адрес сервера лучше скрыть.

## 5. После тестов

```bash
sudo rm -f /etc/ssh/sshd_config.d/00-reviveguard-*.conf /etc/ssh/sshd_config.d/99-*.conf
sudo sshd -t && sudo systemctl reload ssh
```

Либо просто восстановите снапшот или удалите VPS.

## 6. Если потеряли доступ

Войдите через консоль провайдера (VNC/Rescue) и выполните
`sudo rm -f /etc/ssh/sshd_config.d/00-reviveguard-*.conf && sudo systemctl reload ssh`.
