# БИТВА ШКОЛ — Render: тестовый запуск

## 0. Что должно быть в GitHub

В корне репозитория должны лежать именно эти элементы:

- Dockerfile
- docker-compose.yml
- render.yaml
- app/
- static/
- data/
- requirements.txt

Не оставляйте их внутри дополнительной папки.

## 1. Вариант A — рекомендованный: Blueprint

1. На Render откройте Dashboard.
2. Нажмите **New + → Blueprint**.
3. Выберите GitHub-репозиторий `lapiuser/schoolfight` или ваш актуальный репозиторий.
4. Выберите ветку `main`.
5. Render найдёт `render.yaml`.
6. Проверьте, что создаются два ресурса:
   - Web Service `bitva-shkol`
   - Postgres `bitva-shkol-db`
7. Подтвердите создание.

`render.yaml` уже задаёт Dockerfile, Docker context, health check и связь `DATABASE_URL` с Postgres.

## 2. Turnstile для теста

Для первой проверки можно использовать официальные тестовые ключи Cloudflare Turnstile. Они предназначены для тестов и работают на localhost и dev-доменах. Не используйте их в production.

Site Key:
`1x00000000000000000000AA`

Secret Key:
`1x0000000000000000000000000000000AA`

В Render задайте:

`TURNSTILE_ENABLED=true`
`TURNSTILE_SITE_KEY=<test-site-key>`
`TURNSTILE_SECRET_KEY=<test-secret-key>`

## 3. Вариант B — уже существующий Web Service

Если сервис уже создан вручную:

**Settings → Build & Deploy**

Root Directory: пусто

Dockerfile Path:
`./Dockerfile`

Docker Build Context Directory:
`.`

После этого создайте отдельный Render Postgres и добавьте его connection string как `DATABASE_URL`, либо пересоздайте сервис через Blueprint.

## 4. Обязательные environment variables

Минимум для теста:

`DATABASE_URL` — строка подключения Render Postgres
`WEB_CONCURRENCY=1`
`HOST=0.0.0.0`
`COOKIE_SECURE=true`
`TURNSTILE_ENABLED=true`
`TURNSTILE_SITE_KEY=<test-site-key>`
`TURNSTILE_SECRET_KEY=<test-secret-key>`
`ADMIN_USERNAME=nfu93amonyunker`
`ADMIN_PASSWORD=<ваш пароль>`
`CLICK_LIMIT_PER_MINUTE=800`
`CLICK_MAX_PER_REQUEST=800`
`CLICK_BURST_LIMIT_5S=800`
`ACTOR_CLICK_LIMIT_PER_MINUTE=800`
`ACTOR_BURST_LIMIT_5S=800`
`IP_REQUEST_LIMIT_PER_MINUTE=120`
`IP_DAILY_CLICK_LIMIT=24000`

`SECRET_KEY` должен быть длинным случайным значением. В Blueprint он генерируется автоматически.

`DONATION_URL` пока можно оставить тестовой или указать свою.

## 5. После деплоя

Откройте Render URL.

Проверьте:

1. Россия → город → категория → школа.
2. Для Калининграда должно быть только 75 старых заведений.
3. Откройте школу и пройдите Turnstile.
4. Быстро нажмите несколько раз. Клиент копит клики и отправляет их пачкой примерно раз в 5 секунд.
5. Откройте рейтинг.
6. Переключите **Школы** → **Города России**.
7. В каждом режиме должна подсвечиваться только одна выбранная сущность.
8. В «О проекте» проверьте `@lapiduser` и кнопку поддержки.
9. Откройте `/admin`, войдите и проверьте журнал abuse.
10. В админке добавьте тестовую школу и фотографию.
11. В статистике проверьте `Всего посетителей`, `Сейчас на сайте`, `Всего кликов`, `Школ играет` и график кликов/с за последние 5 секунд.

## 6. Тест лимита

Лимит 800 считается сервером по скользящему окну в 60 секунд. Отдельный 800/5s предел не позволяет одним пакетом мгновенно превысить разумный burst.

Смена cookie сама по себе не сбрасывает квоту: дополнительно действует fingerprint уровня IP-подсети + User-Agent. Это специально добавлено против старой схемы, когда удаление/замена cookie позволяло создавать новую личность.

Это не абсолютная защита от распределённой атаки из большого числа сетей. Для production используйте сетевую DDoS-защиту отдельно от CAPTCHA.

## 7. Важное ограничение Render Free

Render Free подходит для теста, но не для постоянного рейтинга:
- Web Service засыпает после простоя.
- Файловая система эфемерная.
- Free Postgres ограничен 1 GB и истекает через 30 дней.

Поэтому реальные пользовательские фотографии и постоянный рейтинг переносите на Timeweb/VDS.
