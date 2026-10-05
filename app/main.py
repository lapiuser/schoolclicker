from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen

from fastapi import Cookie, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from .config import (
    SECRET_KEY, ABOUT_TEXT, ACTIVE_USER_SECONDS, ADMIN_PASSWORD, ADMIN_SESSION_HOURS,
    ADMIN_USERNAME, CAPTCHA_SESSION_MINUTES, CLICK_BURST_LIMIT_5S,
    CLICK_LIMIT_PER_MINUTE, CLICK_MAX_PER_REQUEST, COOKIE_SECURE,
    ACTOR_CLICK_LIMIT_PER_MINUTE, ACTOR_BURST_LIMIT_5S,
    DONATION_URL, EVENT_RETENTION_SECONDS, IP_DAILY_CLICK_LIMIT,
    IP_REQUEST_LIMIT_PER_MINUTE, MAX_UPLOAD_MB, STATS_REFRESH_SECONDS,
    TURNSTILE_ENABLED, TURNSTILE_SECRET_KEY, TURNSTILE_SITE_KEY, AUTHOR_WORDS,
)
from .db import (
    AbuseEvent, AdminSession, BlockedIdentity, ClickEvent, DailyVisitor,
    IpDailyUsage, School, SessionLocal, UsedRequest, VoterUsage,
    VisitorIdentity, init_db, utcnow, school_key, school_id,
)
from .schools import CATEGORY_LABELS, CATEGORY_ORDER, SCHOOLS, asset_paths, TYPE_TO_CATEGORY

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "schools"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

CLICK_COOKIE = "bitva_device"
ADMIN_COOKIE = "bitva_admin"
SECRET_KEY_BYTES = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()


def today_key() -> str:
    return utcnow().strftime("%Y-%m-%d")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def clean_text(value: str, max_len: int) -> str:
    return " ".join(str(value or "").strip().split())[:max_len]


def safe_slug(value: str, max_len: int = 60) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9а-яё_-]+", "_", value, flags=re.IGNORECASE)
    value = re.sub(r"_+", "_", value).strip("_")
    return (value or "school")[:max_len]


def client_ip(request: Request) -> str:
    # Only trust proxy headers when the deployment proxy overwrites them.
    # Caddy/Cloudflare in production do this; direct local traffic falls back to socket IP.
    for header in ("CF-Connecting-IP", "X-Real-IP"):
        value = request.headers.get(header, "").strip()
        if value:
            return value
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def ip_prefix(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return f"{net.network_address}/24"
        net = ipaddress.ip_network(f"{ip}/64", strict=False)
        return f"{net.network_address}/64"
    except ValueError:
        return ip[:120]


def identity_from_request(request: Request, response: Response) -> tuple[str, str, str, str]:
    device_id = request.cookies.get(CLICK_COOKIE, "").strip()
    if not device_id or len(device_id) > 120:
        device_id = secrets.token_urlsafe(32)
        response.set_cookie(CLICK_COOKIE, device_id, max_age=31536000, httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/")
    prefix = ip_prefix(client_ip(request))
    ua = clean_text(request.headers.get("user-agent", "unknown"), 300)
    ua_hash = hashlib.sha256(ua.encode("utf-8")).hexdigest()
    material = f"{device_id}|{prefix}|{ua_hash}"
    identity = hmac.new(SECRET_KEY_BYTES, material.encode("utf-8"), hashlib.sha256).hexdigest()
    return identity, prefix, ua_hash, device_id


def ensure_identity(request: Request, response: Response) -> tuple[str, str, str]:
    identity, prefix, ua_hash, _ = identity_from_request(request, response)
    now = utcnow()
    with SessionLocal() as db:
        row = db.get(VisitorIdentity, identity)
        if row is None:
            db.add(VisitorIdentity(identity_hash=identity, ip_prefix=prefix, user_agent_hash=ua_hash, created_at=now, last_seen=now))
        else:
            row.ip_prefix = prefix
            row.user_agent_hash = ua_hash
            row.last_seen = now
        db.commit()
    return identity, prefix, ua_hash


def blocked(db, identity: str) -> bool:
    return db.get(BlockedIdentity, identity) is not None


def log_abuse(db, event_type: str, identity: str | None, prefix: str | None, details: str) -> None:
    cutoff = utcnow() - timedelta(seconds=60)
    q = db.query(AbuseEvent).filter(AbuseEvent.event_type == event_type, AbuseEvent.created_at >= cutoff)
    if identity:
        q = q.filter(AbuseEvent.identity_hash == identity)
    elif prefix:
        q = q.filter(AbuseEvent.ip_prefix == prefix)
    if q.first() is not None:
        return
    db.add(AbuseEvent(event_type=event_type, identity_hash=identity, ip_prefix=prefix, details=details[:1000], created_at=utcnow()))


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return
    try:
        if urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(status_code=403, detail="Недопустимый источник запроса")
    except ValueError:
        raise HTTPException(status_code=403, detail="Недопустимый источник запроса")


def verify_turnstile(token: str, remote_ip: str | None = None) -> bool:
    if not TURNSTILE_ENABLED:
        return True
    if not TURNSTILE_SECRET_KEY or not token:
        return False
    payload = json.dumps({"secret": TURNSTILE_SECRET_KEY, "response": token, "remoteip": remote_ip}).encode("utf-8")
    req = URLRequest("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=5) as result:
            data = json.loads(result.read(8192).decode("utf-8"))
        return bool(data.get("success"))
    except Exception:
        return False


def ensure_usage(db, identity: str, now: datetime) -> VoterUsage:
    usage = db.get(VoterUsage, identity)
    day = today_key()
    if usage is None:
        usage = VoterUsage(identity_hash=identity, day=day, clicks=0)
        db.add(usage)
        db.flush()
    elif usage.day != day:
        usage.day = day
        usage.clicks = 0
        usage.last_click_at = None
        usage.captcha_verified_until = None
    return usage


def captcha_is_verified(db, identity: str, now: datetime) -> bool:
    usage = db.get(VoterUsage, identity)
    return bool(usage and usage.captcha_verified_until and usage.captcha_verified_until > now)


def recent_clicks_for_identity(db, identity: str, now: datetime, seconds: int) -> int:
    value = db.query(func.coalesce(func.sum(ClickEvent.clicks), 0)).filter(
        ClickEvent.identity_hash == identity,
        ClickEvent.created_at >= now - timedelta(seconds=seconds),
    ).scalar() or 0
    return int(value)


def recent_clicks_for_actor(db, ip_prefix: str, ua_hash: str, now: datetime, seconds: int) -> int:
    # Secondary quota that does not depend on the cookie.
    # This specifically prevents the old "delete/replace cookie" bypass.
    value = db.query(func.coalesce(func.sum(ClickEvent.clicks), 0)).join(
        VisitorIdentity, VisitorIdentity.identity_hash == ClickEvent.identity_hash
    ).filter(
        VisitorIdentity.ip_prefix == ip_prefix,
        VisitorIdentity.user_agent_hash == ua_hash,
        ClickEvent.created_at >= now - timedelta(seconds=seconds),
    ).scalar() or 0
    return int(value)


def school_payload(row: School, include_image: bool = True) -> dict:
    result = {
        "id": row.id,
        "name": row.name,
        "category": row.category,
        "category_label": row.category_label,
        "country": row.country,
        "region": row.region or "",
        "city": row.city,
    }
    if include_image:
        result["images"] = asset_paths(row)
    return result


class ClickPayload(BaseModel):
    school_id: str = Field(min_length=1, max_length=100)
    clicks: int = Field(ge=1, le=CLICK_MAX_PER_REQUEST)
    request_id: str = Field(min_length=16, max_length=80)


class HeartbeatPayload(BaseModel):
    school_id: str | None = None


class CaptchaPayload(BaseModel):
    token: str = Field(min_length=1, max_length=2048)


class AdminLoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)
    captcha_token: str | None = Field(default=None, max_length=2048)


class BlockPayload(BaseModel):
    identity_hash: str = Field(min_length=32, max_length=64)
    reason: str = Field(default="", max_length=500)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="БИТВА ШКОЛ", version="3.0.0", lifespan=lifespan)
app.mount("/assets", StaticFiles(directory=str(STATIC_DIR)), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/assets/uploads/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    elif path.startswith("/assets/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


@app.get("/api/config")
def public_config():
    return {
        "site_name": "БИТВА ШКОЛ",
        "captcha_enabled": TURNSTILE_ENABLED,
        "turnstile_site_key": TURNSTILE_SITE_KEY if TURNSTILE_ENABLED else "",
        "donation_url": DONATION_URL,
        "stats_refresh_seconds": STATS_REFRESH_SECONDS,
        "click_limit_per_minute": CLICK_LIMIT_PER_MINUTE,
        "click_max_per_request": CLICK_MAX_PER_REQUEST,
        "actor_click_limit_per_minute": ACTOR_CLICK_LIMIT_PER_MINUTE,
    }


@app.get("/api/session")
def session(response: Response, request: Request):
    identity, prefix, ua_hash = ensure_identity(request, response)
    now = utcnow(); day = today_key()
    with SessionLocal() as db:
        if blocked(db, identity):
            return {"ok": True, "visitor": identity[:12], "clicks_minute": 0, "remaining": 0, "limit_per_minute": CLICK_LIMIT_PER_MINUTE, "captcha_required": TURNSTILE_ENABLED}
        row = db.query(DailyVisitor).filter(DailyVisitor.day == day, DailyVisitor.identity_hash == identity).first()
        if row:
            row.last_seen = now
        else:
            db.add(DailyVisitor(day=day, identity_hash=identity, last_seen=now))
        ensure_usage(db, identity, now)
        db.commit()
        clicks_minute = recent_clicks_for_identity(db, identity, now, 60)
    return {
        "ok": True,
        "visitor": identity[:12],
        "clicks_minute": clicks_minute,
        "remaining": max(0, CLICK_LIMIT_PER_MINUTE - clicks_minute),
        "limit_per_minute": CLICK_LIMIT_PER_MINUTE,
        "captcha_required": TURNSTILE_ENABLED,
    }


@app.post("/api/captcha/verify")
def captcha_verify(payload: CaptchaPayload, request: Request, response: Response):
    require_same_origin(request)
    identity, prefix, _ = ensure_identity(request, response)
    now = utcnow()
    with SessionLocal() as db:
        if blocked(db, identity):
            raise HTTPException(status_code=403, detail="Доступ ограничен")
        if not verify_turnstile(payload.token, client_ip(request)):
            log_abuse(db, "invalid_captcha", identity, prefix, "Turnstile verification failed")
            db.commit(); raise HTTPException(status_code=403, detail="Проверка не пройдена")
        usage = ensure_usage(db, identity, now)
        usage.captcha_verified_until = now + timedelta(minutes=CAPTCHA_SESSION_MINUTES)
        db.commit()
    return {"ok": True}


@app.get("/api/cities")
def cities():
    with SessionLocal() as db:
        rows = db.query(School.city, func.count(School.id)).filter(School.is_active == 1).group_by(School.city).order_by(School.city.asc()).all()
        return {"country": "Россия", "cities": [{"name": city, "count": int(count)} for city, count in rows]}


@app.get("/api/cities/{city}/categories")
def city_categories(city: str):
    city = clean_text(city, 160)
    with SessionLocal() as db:
        rows = db.query(School).filter(School.is_active == 1, School.city == city).order_by(School.category.asc(), School.name.asc()).all()
        grouped: dict[str, list[dict]] = {}
        for row in rows:
            grouped.setdefault(row.category, []).append(school_payload(row, include_image=False))
        categories = [{"id": key, "name": CATEGORY_LABELS.get(key, key), "schools": grouped[key]} for key in CATEGORY_ORDER if key in grouped]
        if not categories:
            raise HTTPException(status_code=404, detail="Город не найден")
        return {"city": city, "categories": categories}


@app.get("/api/schools")
def schools_compat():
    # Compatibility/debug endpoint: compact catalog without image URLs.
    with SessionLocal() as db:
        rows = db.query(School).filter(School.is_active == 1).order_by(School.city.asc(), School.category.asc(), School.name.asc()).all()
        return {"items": [school_payload(row, include_image=False) for row in rows]}


@app.get("/api/schools/{school_id}")
def school_detail(school_id: str):
    with SessionLocal() as db:
        row = db.get(School, school_id)
        if not row or not row.is_active:
            raise HTTPException(status_code=404, detail="Учебное заведение не найдено")
        return school_payload(row, include_image=True)


@app.get("/api/leaderboard")
def leaderboard(school_id: str | None = None, limit: int = 100, scope: str = "schools"):
    limit = max(10, min(int(limit), 100))
    scope = (scope or "schools").strip().lower()
    if scope not in {"schools", "cities"}:
        scope = "schools"
    with SessionLocal() as db:
        if scope == "cities":
            rows = db.query(
                School.city.label("city"),
                func.coalesce(func.sum(School.real_clicks), 0).label("clicks"),
                func.count(School.id).label("school_count"),
            ).filter(School.is_active == 1).group_by(School.city).order_by(text("clicks DESC"), School.city.asc()).limit(limit).all()
            items = [{
                "rank": idx,
                "id": f"city:{row.city}",
                "name": row.city,
                "city": row.city,
                "region": "Россия",
                "clicks": int(row.clicks or 0),
                "school_count": int(row.school_count or 0),
                "kind": "city",
            } for idx, row in enumerate(rows, start=1)]
            mine = None
            if school_id:
                target = db.get(School, school_id)
                if target and target.is_active:
                    city_sums = db.query(
                        School.city,
                        func.coalesce(func.sum(School.real_clicks), 0).label("clicks"),
                    ).filter(School.is_active == 1).group_by(School.city).all()
                    city_total = next((int(v or 0) for city, v in city_sums if city == target.city), 0)
                    rank = 1 + sum(1 for city, value in city_sums if int(value or 0) > city_total or (int(value or 0) == city_total and str(city) < str(target.city)))
                    school_count = db.query(func.count(School.id)).filter(School.is_active == 1, School.city == target.city).scalar() or 0
                    mine = {"rank": int(rank), "id": f"city:{target.city}", "name": target.city, "city": target.city, "region": "Россия", "clicks": city_total, "school_count": int(school_count), "kind": "city"}
            return {"scope": "cities", "items": items, "mine": mine}

        rows = db.query(School).filter(School.is_active == 1).order_by(School.real_clicks.desc(), School.id.asc()).limit(limit).all()
        items = [{"rank": idx, "id": row.id, "name": row.name, "city": row.city, "region": row.region or "Россия", "clicks": int(row.real_clicks), "kind": "school"} for idx, row in enumerate(rows, start=1)]
        mine = None
        if school_id:
            target = db.get(School, school_id)
            if target and target.is_active:
                better = db.query(func.count(School.id)).filter(School.is_active == 1, School.real_clicks > target.real_clicks).scalar() or 0
                same_before = db.query(func.count(School.id)).filter(School.is_active == 1, School.real_clicks == target.real_clicks, School.id < target.id).scalar() or 0
                mine = {"rank": int(better + same_before + 1), "id": target.id, "name": target.name, "city": target.city, "region": target.region or "Россия", "clicks": int(target.real_clicks), "kind": "school"}
        return {"scope": "schools", "items": items, "mine": mine}


@app.get("/api/stats")
def stats():
    now = utcnow(); cutoff = now - timedelta(seconds=ACTIVE_USER_SECONDS)
    epoch = int(now.replace(tzinfo=timezone.utc).timestamp())
    points = list(range(epoch - 4, epoch + 1))
    with SessionLocal() as db:
        total_visitors = db.query(func.count(VisitorIdentity.identity_hash)).scalar() or 0
        active_users = db.query(func.count(VisitorIdentity.identity_hash)).filter(VisitorIdentity.last_seen >= cutoff).scalar() or 0
        total = db.query(func.coalesce(func.sum(School.real_clicks), 0)).filter(School.is_active == 1).scalar() or 0
        schools_playing = db.query(func.count(School.id)).filter(School.is_active == 1, School.real_clicks > 0).scalar() or 0
        recent = db.query(ClickEvent).filter(ClickEvent.created_at >= now - timedelta(seconds=7)).all()
    bucket = {x: 0 for x in points}
    for e in recent:
        sec = int(e.created_at.replace(tzinfo=timezone.utc).timestamp())
        if sec in bucket:
            bucket[sec] += int(e.clicks)
    values = [bucket[x] for x in points]
    return {
        "total_visitors": int(total_visitors),
        "active_users": int(active_users),
        "total_clicks": int(total),
        "schools_playing": int(schools_playing),
        "cps_current": int(values[-1]),
        "cps_avg_5s": round(sum(values) / 5, 1),
        "cps_last_5_seconds": values,
        "click_limit_per_minute": CLICK_LIMIT_PER_MINUTE,
    }


@app.get("/api/about")
def about():
    return {"title": "О проекте", "text": ABOUT_TEXT, "author_title": "СЛОВА АВТОРА", "author_words": AUTHOR_WORDS, "production": "Anton Ljungberg Production", "donation_url": DONATION_URL, "contact_url": "https://t.me/lapiduser", "contact_text": "Прислать фотографию своей школы → @lapiduser"}


@app.post("/api/heartbeat")
def heartbeat(payload: HeartbeatPayload, request: Request, response: Response):
    require_same_origin(request)
    identity, prefix, ua_hash = ensure_identity(request, response)
    now = utcnow(); day = today_key()
    with SessionLocal() as db:
        if blocked(db, identity):
            return {"ok": False}
        row = db.query(DailyVisitor).filter(DailyVisitor.day == day, DailyVisitor.identity_hash == identity).first()
        if row: row.last_seen = now
        else: db.add(DailyVisitor(day=day, identity_hash=identity, last_seen=now))
        visitor = db.get(VisitorIdentity, identity)
        if visitor: visitor.last_seen = now; visitor.ip_prefix = prefix; visitor.user_agent_hash = ua_hash
        db.commit()
    return {"ok": True}


@app.post("/api/clicks")
def clicks(payload: ClickPayload, request: Request, response: Response):
    require_same_origin(request)
    identity, prefix, ua_hash = ensure_identity(request, response)
    now = utcnow()
    current_ua_hash = hashlib.sha256(clean_text(request.headers.get("user-agent", "unknown"), 300).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(ua_hash, current_ua_hash):
        raise HTTPException(status_code=403, detail="Проверка запроса не пройдена")
    suspicious_ua = any(x in request.headers.get("user-agent", "").lower() for x in ("curl/", "python-requests", "wget/", "scrapy/", "httpclient"))
    with SessionLocal() as db:
        cleanup_cutoff = now - timedelta(seconds=EVENT_RETENTION_SECONDS)
        db.query(ClickEvent).filter(ClickEvent.created_at < cleanup_cutoff).delete(synchronize_session=False)
        db.query(UsedRequest).filter(UsedRequest.created_at < cleanup_cutoff).delete(synchronize_session=False)
        target = db.get(School, payload.school_id)
        if not target or not target.is_active:
            raise HTTPException(status_code=404, detail="Учебное заведение не найдено")
        if blocked(db, identity):
            log_abuse(db, "blocked_identity", identity, prefix, "Click from blocked identity"); db.commit()
            raise HTTPException(status_code=403, detail="Доступ ограничен")
        if TURNSTILE_ENABLED and not captcha_is_verified(db, identity, now):
            log_abuse(db, "captcha_required", identity, prefix, "Click without verified Turnstile session"); db.commit()
            raise HTTPException(status_code=403, detail="Пройдите проверку CAPTCHA")
        if suspicious_ua:
            log_abuse(db, "suspicious_user_agent", identity, prefix, request.headers.get("user-agent", "")[:300]); db.commit()
            raise HTTPException(status_code=403, detail="Запрос заблокирован")

        usage = db.execute(select(VoterUsage).where(VoterUsage.identity_hash == identity).with_for_update()).scalar_one_or_none()
        if usage is None:
            usage = VoterUsage(identity_hash=identity, day=today_key(), clicks=0)
            db.add(usage); db.flush()
        used = db.get(UsedRequest, payload.request_id)
        if used is not None:
            minute_used = recent_clicks_for_identity(db, identity, now, 60)
            return {"ok": True, "accepted": 0, "rejected": payload.clicks, "duplicate": True, "remaining": max(0, CLICK_LIMIT_PER_MINUTE - minute_used), "limit_per_minute": CLICK_LIMIT_PER_MINUTE}

        minute_used = recent_clicks_for_identity(db, identity, now, 60)
        actor_minute_used = recent_clicks_for_actor(db, prefix, ua_hash, now, 60)
        if minute_used >= CLICK_LIMIT_PER_MINUTE or actor_minute_used >= ACTOR_CLICK_LIMIT_PER_MINUTE:
            log_abuse(db, "minute_click_limit", identity, prefix, f"identity={minute_used};actor={actor_minute_used};limit={CLICK_LIMIT_PER_MINUTE}"); db.commit()
            return {"ok": True, "accepted": 0, "rejected": payload.clicks, "remaining": 0, "limit_per_minute": CLICK_LIMIT_PER_MINUTE}

        burst = recent_clicks_for_identity(db, identity, now, 5)
        actor_burst = recent_clicks_for_actor(db, prefix, ua_hash, now, 5)
        if burst >= CLICK_BURST_LIMIT_5S or burst + payload.clicks > CLICK_BURST_LIMIT_5S or actor_burst >= ACTOR_BURST_LIMIT_5S or actor_burst + payload.clicks > ACTOR_BURST_LIMIT_5S:
            log_abuse(db, "click_burst_limit", identity, prefix, f"identity={burst};actor={actor_burst};requested={payload.clicks}"); db.commit()
            raise HTTPException(status_code=429, detail="Слишком много кликов за 5 секунд")

        req_count = db.query(func.count(UsedRequest.request_id)).filter(UsedRequest.ip_prefix == prefix, UsedRequest.created_at >= now - timedelta(seconds=60)).scalar() or 0
        if req_count >= IP_REQUEST_LIMIT_PER_MINUTE:
            log_abuse(db, "request_rate_limit", identity, prefix, f"requests={req_count}"); db.commit()
            raise HTTPException(status_code=429, detail="Слишком много запросов")

        ip_usage = db.execute(select(IpDailyUsage).where(IpDailyUsage.ip_prefix == prefix, IpDailyUsage.day == today_key()).with_for_update()).scalar_one_or_none()
        if ip_usage is None:
            ip_usage = IpDailyUsage(ip_prefix=prefix, day=today_key(), clicks=0, updated_at=now); db.add(ip_usage); db.flush()
        if ip_usage.clicks >= IP_DAILY_CLICK_LIMIT or ip_usage.clicks + payload.clicks > IP_DAILY_CLICK_LIMIT:
            log_abuse(db, "ip_daily_click_limit", identity, prefix, f"ip_limit={IP_DAILY_CLICK_LIMIT};used={ip_usage.clicks}"); db.commit()
            raise HTTPException(status_code=429, detail="Слишком много активности с одной сети")

        capacity = min(
            CLICK_LIMIT_PER_MINUTE - minute_used,
            ACTOR_CLICK_LIMIT_PER_MINUTE - actor_minute_used,
            CLICK_BURST_LIMIT_5S - burst,
            ACTOR_BURST_LIMIT_5S - actor_burst,
            IP_DAILY_CLICK_LIMIT - ip_usage.clicks,
        )
        accepted = max(0, min(payload.clicks, capacity))
        rejected = payload.clicks - accepted
        if accepted:
            target.real_clicks += accepted
            usage.clicks += accepted
            usage.last_click_at = now
            ip_usage.clicks += accepted
            ip_usage.updated_at = now
            db.add(ClickEvent(school_id=target.id, identity_hash=identity, clicks=accepted, created_at=now))
        db.add(UsedRequest(request_id=payload.request_id, identity_hash=identity, ip_prefix=prefix, created_at=now))
        if rejected:
            log_abuse(db, "click_cap", identity, prefix, f"requested={payload.clicks};accepted={accepted}")
        db.commit()
        remaining = max(0, CLICK_LIMIT_PER_MINUTE - minute_used - accepted)
        return {"ok": True, "accepted": accepted, "rejected": rejected, "remaining": remaining, "limit_per_minute": CLICK_LIMIT_PER_MINUTE}


# ---------- Admin ----------

def require_admin(token: str | None):
    if not token: raise HTTPException(status_code=401, detail="Требуется вход администратора")
    with SessionLocal() as db:
        row = db.get(AdminSession, hash_token(token))
        if not row or row.expires_at <= utcnow(): raise HTTPException(status_code=401, detail="Сессия администратора истекла")


@app.get("/api/admin/me")
def admin_me(bitva_admin: str | None = Cookie(default=None)):
    if not bitva_admin: return {"authenticated": False}
    try: require_admin(bitva_admin)
    except HTTPException: return {"authenticated": False}
    return {"authenticated": True, "username": ADMIN_USERNAME}


@app.post("/api/admin/login")
def admin_login(payload: AdminLoginPayload, request: Request, response: Response):
    require_same_origin(request)
    if not ADMIN_PASSWORD: raise HTTPException(status_code=503, detail="ADMIN_PASSWORD не задан на сервере")
    prefix = ip_prefix(client_ip(request)); since = utcnow() - timedelta(minutes=15)
    with SessionLocal() as db:
        failed = db.query(func.count(AbuseEvent.id)).filter(AbuseEvent.event_type == "admin_login_failed", AbuseEvent.ip_prefix == prefix, AbuseEvent.created_at >= since).scalar() or 0
        if failed >= 8: raise HTTPException(status_code=429, detail="Слишком много попыток входа. Попробуйте позже")
        if TURNSTILE_ENABLED and not verify_turnstile(payload.captcha_token or "", client_ip(request)):
            log_abuse(db, "admin_invalid_captcha", None, prefix, "admin login captcha failed"); db.commit(); raise HTTPException(status_code=403, detail="Проверка CAPTCHA не пройдена")
        if not (hmac.compare_digest(payload.username, ADMIN_USERNAME) and hmac.compare_digest(payload.password, ADMIN_PASSWORD)):
            log_abuse(db, "admin_login_failed", None, prefix, "invalid credentials"); db.commit(); raise HTTPException(status_code=401, detail="Неверные данные")
        token = secrets.token_urlsafe(48); db.add(AdminSession(token_hash=hash_token(token), created_at=utcnow(), expires_at=utcnow()+timedelta(hours=ADMIN_SESSION_HOURS), ip_prefix=prefix)); db.commit()
    response.set_cookie(ADMIN_COOKIE, token, max_age=ADMIN_SESSION_HOURS*3600, httponly=True, secure=COOKIE_SECURE, samesite="strict", path="/")
    return {"ok": True}


@app.post("/api/admin/logout")
def admin_logout(response: Response, request: Request, bitva_admin: str | None = Cookie(default=None)):
    require_same_origin(request)
    if bitva_admin:
        with SessionLocal() as db:
            db.query(AdminSession).filter(AdminSession.token_hash == hash_token(bitva_admin)).delete(synchronize_session=False); db.commit()
    response.delete_cookie(ADMIN_COOKIE, path="/"); return {"ok": True}


@app.get("/api/admin/dashboard")
def admin_dashboard(bitva_admin: str | None = Cookie(default=None)):
    require_admin(bitva_admin)
    with SessionLocal() as db:
        schools_count = db.query(func.count(School.id)).filter(School.is_active == 1).scalar() or 0
        total_clicks = db.query(func.coalesce(func.sum(School.real_clicks), 0)).filter(School.is_active == 1).scalar() or 0
        abuse_count = db.query(func.count(AbuseEvent.id)).scalar() or 0
        blocked_count = db.query(func.count(BlockedIdentity.identity_hash)).scalar() or 0
        source_national = db.query(func.count(School.id)).filter(School.origin == "national", School.is_active == 1).scalar() or 0
        events = db.query(AbuseEvent).order_by(AbuseEvent.created_at.desc()).limit(50).all()
    return {"schools_count": int(schools_count), "total_clicks": int(total_clicks), "abuse_events": int(abuse_count), "blocked_identities": int(blocked_count), "national_schools": int(source_national), "abuse": [{"id":e.id,"created_at":e.created_at.isoformat(),"event_type":e.event_type,"identity":e.identity_hash,"ip_prefix":e.ip_prefix,"details":e.details} for e in events]}


@app.post("/api/admin/block")
def admin_block(payload: BlockPayload, request: Request, bitva_admin: str | None = Cookie(default=None)):
    require_same_origin(request); require_admin(bitva_admin)
    with SessionLocal() as db:
        db.merge(BlockedIdentity(identity_hash=payload.identity_hash, reason=clean_text(payload.reason,500), created_at=utcnow())); db.commit()
    return {"ok": True}


@app.post("/api/admin/unblock")
def admin_unblock(payload: BlockPayload, request: Request, bitva_admin: str | None = Cookie(default=None)):
    require_same_origin(request); require_admin(bitva_admin)
    with SessionLocal() as db:
        db.query(BlockedIdentity).filter(BlockedIdentity.identity_hash == payload.identity_hash).delete(synchronize_session=False); db.commit()
    return {"ok": True}


@app.get("/api/admin/schools")
def admin_schools(page: int = 1, per_page: int = 100, q: str = "", bitva_admin: str | None = Cookie(default=None)):
    require_admin(bitva_admin)
    page = max(1, min(page, 10000)); per_page = max(20, min(per_page, 200)); q = clean_text(q, 120)
    with SessionLocal() as db:
        query = db.query(School)
        if q:
            like = f"%{q}%"; query = query.filter((School.name.ilike(like)) | (School.city.ilike(like)) | (School.region.ilike(like)))
        total = query.count(); rows = query.order_by(School.region.asc().nullslast(), School.city.asc(), School.name.asc()).offset((page-1)*per_page).limit(per_page).all()
    return {"page": page, "per_page": per_page, "total": int(total), "items": [{"id":r.id,"name":r.name,"country":r.country,"region":r.region or "Россия","city":r.city,"category":r.category,"category_label":r.category_label,"clicks":int(r.real_clicks),"image_source":r.image_source,"origin":r.origin,"active":bool(r.is_active)} for r in rows]}


@app.post("/api/admin/schools")
async def admin_add_school(request: Request, bitva_admin: str | None = Cookie(default=None), name: str = Form(...), country: str = Form("Россия"), region: str = Form(""), city: str = Form(...), category: str = Form(...), photo: UploadFile | None = File(default=None)):
    require_same_origin(request); require_admin(bitva_admin)
    name = clean_text(name,500); country = clean_text(country,80) or "Россия"; region = clean_text(region,150) or ""; city = clean_text(city,160); category = clean_text(category,50)
    if not name or not city or category not in CATEGORY_LABELS: raise HTTPException(status_code=400, detail="Заполните название, город и категорию")
    key = school_key(city, category, name)
    school_identifier = school_id(city, category, name)
    photo_source = "placeholder"
    if photo:
        if photo.content_type not in {"image/jpeg","image/png","image/webp"}: raise HTTPException(status_code=400, detail="Фото: только JPG, PNG или WebP")
        raw = await photo.read()
        if len(raw) > MAX_UPLOAD_MB * 1024 * 1024: raise HTTPException(status_code=413, detail=f"Фото слишком большое. Максимум {MAX_UPLOAD_MB} МБ")
        try:
            from PIL import Image, ImageOps
            import io
            img = ImageOps.exif_transpose(Image.open(io.BytesIO(raw)).convert("RGB")); img.thumbnail((1800,1400), Image.Resampling.LANCZOS)
            target_dir = UPLOAD_DIR / school_identifier; target_dir.mkdir(parents=True, exist_ok=True); img.save(target_dir/"photo.webp","WEBP",quality=82,method=6); photo_source = "upload"
        except Exception as exc: raise HTTPException(status_code=400, detail=f"Не удалось обработать изображение: {exc.__class__.__name__}")
    with SessionLocal() as db:
        if db.scalar(select(School).where(School.normalized_key == key)):
            raise HTTPException(status_code=409, detail="Такое учебное заведение уже есть в этом городе и категории")
        db.add(School(id=school_identifier,country=country,region=region or None,city=city,category=category,category_label=CATEGORY_LABELS[category],name=name,folder=f"national/{school_identifier}",normalized_key=key,image_source=photo_source,origin="manual",is_active=1,real_clicks=0,artificial_clicks=0,created_at=utcnow()))
        db.commit()
    return {"ok":True,"school":{"id":school_identifier,"name":name,"city":city}}


@app.get("/admin")
def admin_page(): return FileResponse(STATIC_DIR/"admin.html")


@app.get("/health")
def health(): return {"status":"ok","service":"bitva-shkol","time":utcnow().isoformat()}


@app.get("/")
def index(): return FileResponse(STATIC_DIR/"index.html")
