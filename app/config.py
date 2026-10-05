import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "schools"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'leaderboard.db').as_posix()}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

APP_HOST = os.getenv("HOST", "127.0.0.1")
APP_PORT = int(os.getenv("PORT", "8000"))
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]

# Fair-use protection
# Rolling fair-use limits. There is deliberately no daily voter quota.
CLICK_LIMIT_PER_MINUTE = int(os.getenv("CLICK_LIMIT_PER_MINUTE", "800"))
CLICK_MAX_PER_REQUEST = int(os.getenv("CLICK_MAX_PER_REQUEST", "800"))
CLICK_BURST_LIMIT_5S = int(os.getenv("CLICK_BURST_LIMIT_5S", "800"))
IP_REQUEST_LIMIT_PER_MINUTE = int(os.getenv("IP_REQUEST_LIMIT_PER_MINUTE", "120"))
IP_DAILY_CLICK_LIMIT = int(os.getenv("IP_DAILY_CLICK_LIMIT", "24000"))
ACTOR_CLICK_LIMIT_PER_MINUTE = int(os.getenv("ACTOR_CLICK_LIMIT_PER_MINUTE", "800"))
ACTOR_BURST_LIMIT_5S = int(os.getenv("ACTOR_BURST_LIMIT_5S", "800"))
ACTIVE_USER_SECONDS = int(os.getenv("ACTIVE_USER_SECONDS", "60"))
EVENT_RETENTION_SECONDS = int(os.getenv("EVENT_RETENTION_SECONDS", "900"))

# CAPTCHA
TURNSTILE_ENABLED = os.getenv("TURNSTILE_ENABLED", "false").lower() == "true"
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
CAPTCHA_SESSION_MINUTES = int(os.getenv("CAPTCHA_SESSION_MINUTES", "20"))

# Administration
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "nfu93amonyunker")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_SESSION_HOURS = int(os.getenv("ADMIN_SESSION_HOURS", "12"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "8"))

# UI/content
DONATION_URL = os.getenv("DONATION_URL", "https://www.donationalerts.com/")
AUTHOR_WORDS = os.getenv(
    "AUTHOR_WORDS",
    "БИТВА ШКОЛ — независимый рейтинг, где учебные заведения соревнуются за реальную поддержку людей. "
    "Количество кликов ограничено и проверяется сервером, чтобы результат оставался честным.",
)
ABOUT_TEXT = os.getenv(
    "ABOUT_TEXT",
    "БИТВА ШКОЛ — интерактивный рейтинг учебных заведений России. "
    "Выберите регион, город и школу, затем поддерживайте её кликами. "
    "Новые школы и фотографии добавляются вручную через панель администратора.",
)

# Kept for compatibility with the older project.
DEMO_ACTIVITY_ENABLED = os.getenv("DEMO_ACTIVITY_ENABLED", "false").lower() == "true"
RATING_REFRESH_SECONDS = int(os.getenv("RATING_REFRESH_SECONDS", "5"))
STATS_REFRESH_SECONDS = int(os.getenv("STATS_REFRESH_SECONDS", "15"))
