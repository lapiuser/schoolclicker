# БИТВА ШКОЛ — Timeweb Cloud: подробный production-запуск

Цель: один и тот же проект после теста запустить на собственном VDS без отдельной версии сайта.

## 1. Что купить

Рекомендуемый старт:

- Ubuntu 24.04 LTS
- 2 vCPU
- 2–4 GB RAM
- 30–40 GB SSD/NVMe

Для большого числа фото при дальнейшем росте можно увеличить диск.

Если хотите использовать DDoS-защиту Timeweb Cloud для Cloud Server, выбирайте локацию, для которой она доступна (сейчас документация указывает Санкт-Петербург и Москву).

## 2. DDoS-защита

В панели Timeweb Cloud:

**Облачные серверы → ваш сервер → Сеть → Защита от DDoS → Включить**

У Timeweb Cloud для Cloud Server доступны уровни L3/L4, а L7 подключается отдельно через поддержку; документация указывает доступность сервиса для серверов в Санкт-Петербурге и Москве.

CAPTCHA и DDoS — разные уровни защиты:

- Turnstile отсекает значительную часть автоматизированного поведения на уровне приложения.
- DDoS-защита фильтрует сетевой поток до приложения.
- Серверные лимиты защищают сами операции рейтинга.

## 3. Создайте сервер

В панели Timeweb Cloud создайте Cloud Server.

После создания запишите:

- IPv4
- root-пароль или SSH-ключ

В Windows PowerShell:

```powershell
ssh root@IP_СЕРВЕРА
```

## 4. DNS домена

Для домена `bitvashkol.ru` пример:

```text
Тип: A
Имя: @
Значение: IP_СЕРВЕРА
```

Для `www`:

```text
Тип: CNAME
Имя: www
Значение: bitvashkol.ru
```

В Timeweb DNS-редактор находится в управлении доменом. После изменения дождитесь обновления DNS.

## 5. Обновите Ubuntu

После SSH:

```bash
apt update && apt upgrade -y
```

Установите базовые пакеты:

```bash
apt install -y ca-certificates curl git nano ufw
```

## 6. Firewall

Разрешите SSH, HTTP и HTTPS:

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status
```

Порт PostgreSQL наружу не открывайте.

Порт FastAPI `8000` наружу тоже не открывайте: в этом проекте его принимает только внутренний Docker-сервис Caddy.

## 7. Установите Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Проверьте:

```bash
docker --version
docker compose version
```

## 8. Получите код

В GitHub корень репозитория должен содержать:

```text
Dockerfile
docker-compose.yml
Caddyfile
render.yaml
app/
static/
data/
requirements.txt
```

На сервере:

```bash
git clone https://github.com/lapiuser/schoolfight.git /opt/bitva-shkol
cd /opt/bitva-shkol
```

Если репозиторий называется иначе — замените URL.

## 9. Создайте production .env

```bash
cp .env.production.example .env
nano .env
```

Минимальный набор:

```env
SITE_DOMAIN=ВАШ_ДОМЕН
POSTGRES_DB=bitva
POSTGRES_USER=bitva
POSTGRES_PASSWORD=СИЛЬНЫЙ_ПАРОЛЬ_БД
SECRET_KEY=ДЛИННАЯ_СЛУЧАЙНАЯ_СТРОКА
ADMIN_USERNAME=nfu93amonyunker
ADMIN_PASSWORD=ВАШ_ПАРОЛЬ_АДМИНКИ
TURNSTILE_ENABLED=true
TURNSTILE_SITE_KEY=ВАШ_PRODUCTION_SITE_KEY
TURNSTILE_SECRET_KEY=ВАШ_PRODUCTION_SECRET_KEY
DONATION_URL=ВАША_ССЫЛКА_DONATIONALERTS
```

Не публикуйте `.env` в GitHub.

## 10. Создайте production Turnstile

В Cloudflare Dashboard → Turnstile создайте новый widget.

В hostname укажите только ваш реальный домен.

Получите:

- Site Key — можно передавать браузеру.
- Secret Key — хранится только на сервере в `.env`.

Для production НЕ используйте тестовые ключи из документации Cloudflare.

## 11. Первый запуск

```bash
cd /opt/bitva-shkol
docker compose up -d --build
```

Проверьте:

```bash
docker compose ps
```

Должны работать три контейнера:

```text
bitva-shkol db
bitva-shkol app
bitva-shkol caddy
```

Проверка FastAPI изнутри сервера:

```bash
curl -fsS http://127.0.0.1:8000/health
```

Ожидается JSON с `ok: true`.

## 12. Проверка логов

```bash
docker compose logs --tail=100 app
docker compose logs --tail=100 caddy
docker compose logs --tail=100 db
```

На старте приложение выводит количество импортированных записей.

Ожидаемая структура каталога:

- 17,951 национальная исходная строка.
- 104 строки Калининграда из национального CSV пропускаются.
- 75 старых калининградских заведений добавляются из bundled-версии.
- итоговый каталог: 17,922 активных объекта.

## 13. HTTPS

Когда DNS уже направлен на сервер, Caddy принимает 80/443 и автоматически получает Let's Encrypt сертификат.

Откройте:

```text
https://ВАШ_ДОМЕН/
https://ВАШ_ДОМЕН/admin
```

## 14. Первичная проверка сайта

Проверьте по порядку:

1. Выбор города.
2. Выбор категории.
3. Выбор школы.
4. Калининград — только старая подборка из 75 объектов.
5. Turnstile.
6. Несколько кликов.
7. Пачка отправляется примерно раз в 5 секунд.
8. Рейтинг школ.
9. Рейтинг городов.
10. Только одна подсветка выбранной школы/города.
11. `Всего посетителей` не увеличивается от обычного F5.
12. `Школ играет` считает только школы, у которых есть хотя бы один реальный клик.
13. CPS показывает последние 5 секунд.
14. Telegram-кнопка открывает `@lapiduser`.
15. Donation Alerts открывает вашу ссылку.
16. `/admin` принимает заданные учётные данные.
17. Добавление школы с фото работает.

## 15. Фотографии

Фотографии, добавленные администратором, хранятся в:

```text
/opt/bitva-shkol/data/uploads
```

Эта папка монтируется в Docker как постоянный каталог приложения.

## 16. Резервная копия БД

Для базовой резервной копии:

```bash
docker compose exec db pg_dump -U bitva -d bitva > /opt/bitva-shkol/backup.sql
```

Храните резервные копии не только на этом же сервере.

## 17. Обновление сайта

```bash
cd /opt/bitva-shkol
git pull
docker compose up -d --build
```

PostgreSQL находится в Docker volume `postgres_data`, поэтому обычный redeploy контейнеров не сбрасывает рейтинг.

## 18. Быстрый контроль после обновления

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/health
docker compose logs --tail=50 app
```

## 19. Важное по безопасности

Не открывайте наружу 5432 и 8000.

Не храните `ADMIN_PASSWORD`, `SECRET_KEY`, `TURNSTILE_SECRET_KEY` в GitHub.

Не используйте Cloudflare Turnstile test keys в production.

CAPTCHA не является заменой сетевой DDoS-защиты.
