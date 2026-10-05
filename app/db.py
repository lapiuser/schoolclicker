from __future__ import annotations

import csv
import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, create_engine, func, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import DATABASE_URL
from .schools import SCHOOLS, TYPE_TO_CATEGORY, CATEGORY_LABELS

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "institutions.csv"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
if DATABASE_URL.startswith("postgres"):
    engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True, connect_args=connect_args, pool_size=10, max_overflow=20)
else:
    engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").lower().replace("ё", "е")
    value = re.sub(r"[^a-zа-я0-9№]+", " ", value, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", value).strip()


def school_key(city: str, category: str, name: str) -> str:
    return f"{normalize_name(city)}|{category}|{normalize_name(name)}"


def school_id(city: str, category: str, name: str) -> str:
    raw = school_key(city, category, name).encode("utf-8")
    return "ru_" + hashlib.sha256(raw).hexdigest()[:28]


class Base(DeclarativeBase):
    pass


class School(Base):
    __tablename__ = "schools"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    country: Mapped[str] = mapped_column(String(80), default="Россия", nullable=False)
    region: Mapped[str | None] = mapped_column(String(150), nullable=True)
    city: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    category_label: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    folder: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_key: Mapped[str] = mapped_column(String(600), nullable=False)
    image_source: Mapped[str] = mapped_column(String(20), default="placeholder", nullable=False)
    origin: Mapped[str] = mapped_column(String(20), default="national", nullable=False)
    is_active: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    real_clicks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    artificial_clicks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint("normalized_key", name="uq_school_normalized_key"),
        Index("ix_schools_city_category", "city", "category"),
        Index("ix_schools_rank", "real_clicks", "id"),
    )


class VisitorIdentity(Base):
    __tablename__ = "visitor_identities"
    identity_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    ip_prefix: Mapped[str] = mapped_column(String(128), index=True)
    user_agent_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class DailyVisitor(Base):
    __tablename__ = "daily_visitors"
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    identity_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_daily_visitors_day_seen", "day", "last_seen"),)


class VoterUsage(Base):
    __tablename__ = "voter_usage"
    identity_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), index=True)
    clicks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_click_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    captcha_verified_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class UsedRequest(Base):
    __tablename__ = "used_requests"
    request_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    identity_hash: Mapped[str] = mapped_column(String(64), index=True)
    ip_prefix: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class IpDailyUsage(Base):
    __tablename__ = "ip_daily_usage"
    ip_prefix: Mapped[str] = mapped_column(String(128), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    clicks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class ClickEvent(Base):
    __tablename__ = "click_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    school_id: Mapped[str] = mapped_column(String(100), index=True)
    identity_hash: Mapped[str] = mapped_column(String(64), index=True)
    clicks: Mapped[int] = mapped_column(Integer, nullable=False)
    __table_args__ = (Index("ix_click_events_identity_time", "identity_hash", "created_at"),)


class AbuseEvent(Base):
    __tablename__ = "abuse_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    identity_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    ip_prefix: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)


class BlockedIdentity(Base):
    __tablename__ = "blocked_identities"
    identity_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    ip_prefix: Mapped[str | None] = mapped_column(String(128), nullable=True)


def seed_bundled_schools(db) -> int:
    added = 0
    for spec in SCHOOLS:
        key = school_key(spec.city, spec.category, spec.name)
        existing = db.scalar(select(School).where(School.normalized_key == key))
        if existing:
            # Ensure legacy/bundled photo info remains authoritative.
            if existing.image_source != "bundled":
                existing.image_source = "bundled"
                existing.folder = spec.folder
                existing.origin = "bundled"
            continue
        db.add(School(
            id=spec.id,
            country=spec.country,
            region=spec.region,
            city=spec.city,
            category=spec.category,
            category_label=spec.category_label,
            name=spec.name,
            folder=spec.folder,
            normalized_key=key,
            image_source="bundled",
            origin="bundled",
            is_active=1,
            real_clicks=0,
            artificial_clicks=0,
        ))
        added += 1
    if added:
        db.flush()
    return added


def import_national_csv(db) -> int:
    if not CSV_PATH.exists():
        return 0
    added = 0
    # Existing normalized keys are the dedupe source of truth; this makes restarts idempotent.
    existing_keys = set(db.scalars(select(School.normalized_key)).all())
    with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            city = (row.get("city") or "").strip()
            name = (row.get("name") or "").strip()
            type_code = (row.get("type_code") or "").strip().lower()
            country = (row.get("country") or "Россия").strip() or "Россия"
            category = TYPE_TO_CATEGORY.get(type_code)
            if not city or not name or not category:
                continue
            # The first Kaliningrad edition is authoritative for this city.
            # Seed its 75 bundled entries from app/schools.py and ignore the
            # extra Kaliningrad rows that exist in the national source CSV.
            if normalize_name(city) == normalize_name("Калининград"):
                continue
            key = school_key(city, category, name)
            if key in existing_keys:
                continue
            sid = school_id(city, category, name)
            # The source contains city-level nationwide data but no oblast/region field; don't invent one.
            db.add(School(
                id=sid,
                country=country,
                region=None,
                city=city,
                category=category,
                category_label=CATEGORY_LABELS[category],
                name=name,
                folder=f"national/{sid}",
                normalized_key=key,
                image_source="placeholder",
                origin="national",
                is_active=1,
                real_clicks=0,
                artificial_clicks=0,
            ))
            existing_keys.add(key)
            added += 1
            if added % 500 == 0:
                db.flush()
    if added:
        db.flush()
    return added


def prune_old_data(db) -> None:
    # Keep operational tables small enough for a modest VDS.
    cutoff_90 = utcnow().date().fromordinal(utcnow().date().toordinal() - 90).isoformat()
    db.execute(text("DELETE FROM daily_visitors WHERE day < :day"), {"day": cutoff_90})
    cutoff_24h = utcnow().timestamp() - 86400
    # Datetime arithmetic differs between SQLite/Postgres, so skip aggressive SQL on the main event table.
    db.commit()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_bundled_schools(db)
        import_national_csv(db)
        # Keep a simple migration path for a future schema addition.
        db.commit()

        # Helpful startup log for deployment diagnostics.
        total = db.scalar(select(func.count(School.id))) or 0
        source_count = 0
        if CSV_PATH.exists():
            with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as f:
                source_count = max(0, sum(1 for _ in f) - 1)
        print(f"[startup] schools={total} bundled={len(SCHOOLS)} source_rows={source_count}", flush=True)
