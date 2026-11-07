# Тестирование ReviveGuard на реальном сервере (гайд)

Цель: проверить на настоящем Linux-сервере то, что тесты проверяют только на имитации, — прежде
всего SSH-исправления (`sshd -t`, `reload`, откат). **Не запускайте `fix` на боевом сервере.**

## 0. Подготовка (обязательно)

1. Одноразовый VPS: **Debian 12** или **Ubuntu 24.04** (на Ubuntu 22.04 системный Python — 3.10,
   а нужен 3.11+; используйте Debian 12 / Ubuntu 24.04 или поставьте Python 3.11 отдельно).
2. Сделайте **снапшот** VPS в панели провайдера.
3. Убедитесь, что есть **консоль провайдера** (VNC / Rescue) — это ваш выход, если потеряете SSH.
4. Откройте **две** SSH-сессии. Вторую не закрывайте до конца тестов.
5. Создайте отдельного пользователя для проверок и дайте ему ключ:

```bash
sudo adduser --disabled-password --gecos "" rgtest
sudo usermod -aG sudo rgtest
```

## 1. Установка

```bash
sudo apt update && sudo apt install -y git python3-venv
git clone https://github.com/JerryWenz/ReviveGuard.git
cd ReviveGuard
git checkout claude/quirky-franklin-vnj8hz
python3 -m venv ~/rg-venv
~/rg-venv/bin/pip install -e .
~/rg-venv/bin/python -m pytest --version >/dev/null 2>&1 || ~/rg-venv/bin/pip install pytest
~/rg-venv/bin/python -m pytest -q          # тесты на самом сервере
```

### Ubuntu 22.04: сначала поставьте Python 3.11

Системный Python здесь 3.10, а ReviveGuard требует 3.11+. Самый простой путь — PPA deadsnakes:

```bash
sudo apt update && sudo apt install -y software-properties-common git
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt install -y python3.11 python3.11-venv
python3.11 --version      # должно быть 3.11.x
```

В командах установки выше замените `python3 -m venv ~/rg-venv` на
`python3.11 -m venv ~/rg-venv`. Остальное без изменений. На 22.04 стоит fail2ban 0.11 (источник
логов `auto`, файл `/var/log/auth.log`) — это нормально, проверки это учитывают.

Дальше везде `RG="sudo $HOME/rg-venv/bin/reviveguard"`:

```bash
RG="sudo $HOME/rg-venv/bin/reviveguard"
```

## 2. Аудит (только чтение)

```bash
~/rg-venv/bin/reviveguard --lang ru audit            # без root: должно быть предупреждение
$RG --lang ru audit                                    # с root
$RG audit --format json > ~/audit.json
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods'
```

Проверьте: значения в отчёте совпадают с `sshd -T`; без root указан источник «parsed».

## 3. Сценарии SSH-исправлений

Каждый сценарий начинайте с проверки второй сессии и записывайте результат.

**A. Отказ без ключа (защита от lockout).** Пользователь `rgtest` без `authorized_keys`, вход
под ним по паролю:

```bash
$RG --lang ru fix --check SSH-002
```

Ожидание: «Требуется ручное исправление…», **файлы не изменены**
(`ls /etc/ssh/sshd_config.d/`).

**B. Успешное отключение паролей.** Добавьте ключ своему пользователю, проверьте вход по ключу
из **нового** окна, затем:

```bash
$RG fix --check SSH-002        # ответьте y, затем yes
sudo sshd -T | grep passwordauthentication       # ожидание: no
cat /etc/ssh/sshd_config.d/00-reviveguard-passwordauthentication.conf
```

Из третьего окна проверьте: вход по ключу работает; вход по паролю отклоняется.

**C. Откат.**

```bash
$RG history
$RG rollback                  # посмотрите план, подтвердите y
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
`$RG --lang ru audit` → ожидается находка `FW-001`. Затем **разрешите SSH-порт** и включите ufw
вручную (`sudo ufw allow 22/tcp && sudo ufw enable`; порт — ваш), повторите аудит: `FW-001..004` OK.
Откройте порт БД (`sudo ufw allow 3306/tcp`) → ожидается `FW-003`; удалите правило. Попробуйте
`$RG fix --category firewall`: ожидается «вручную», правила не меняются (`sudo ufw status` до/после).

**G. Fail2ban.** `sudo apt install -y fail2ban`; `$RG audit` (без root — пропуск). Чтобы вызвать
`F2B-002`, временно отключите jail: файл `/etc/fail2ban/jail.d/defaults-debian.conf` →
`enabled = false` для `[sshd]`, `sudo fail2ban-client reload`. Затем `$RG fix --check F2B-002`
(y), проверьте `sudo fail2ban-client status`, `sudo fail2ban-client status sshd`, откат
(`$RG rollback`) и `sudo fail2ban-client reload`. Верните `enabled` в исходное состояние.

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
