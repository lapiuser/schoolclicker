@echo off
setlocal
cd /d %~dp0
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 (echo Не удалось создать .venv.& pause& exit /b 1)
)
call ".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (echo Не удалось установить зависимости.& pause& exit /b 1)
set "ADMIN_USERNAME=nfu93amonyunker"
if "%ADMIN_PASSWORD%"=="" set /p "ADMIN_PASSWORD=Пароль админки (в этой сессии не сохраняется): "
set "TURNSTILE_ENABLED=true"
set "TURNSTILE_SITE_KEY=1x00000000000000000000AA"
set "TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA"
set "CLICK_LIMIT_PER_MINUTE=800"
set "CLICK_MAX_PER_REQUEST=800"
set "CLICK_BURST_LIMIT_5S=800"
set "IP_REQUEST_LIMIT_PER_MINUTE=120"
set "IP_DAILY_CLICK_LIMIT=24000"
set "ACTOR_CLICK_LIMIT_PER_MINUTE=800"
set "ACTOR_BURST_LIMIT_5S=800"
set "COOKIE_SECURE=false"
echo.
echo Сайт: http://127.0.0.1:8000
echo CAPTCHA: официальный тестовый режим Cloudflare Turnstile.
call ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
