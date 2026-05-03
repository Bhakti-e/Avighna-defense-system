"""
Database configuration for AVIGHNA Defense
SQLAlchemy setup with PostgreSQL support (SQLite fallback for development)
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
import os
import logging

logger = logging.getLogger(__name__)

# Database URL from environment or default to SQLite
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./avighna_defense.db")

# Determine if using PostgreSQL
is_postgres = DATABASE_URL.startswith("postgresql")

# Engine configuration
engine_kwargs = {
    "echo": False,  # Set to True for SQL debugging
}

# SQLite-specific configuration
if not is_postgres:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    logger.info("Using SQLite database")
else:
    # PostgreSQL-specific configuration
    engine_kwargs["pool_size"] = int(os.environ.get("DB_POOL_SIZE", "10"))
    engine_kwargs["max_overflow"] = int(os.environ.get("DB_MAX_OVERFLOW", "20"))
    engine_kwargs["pool_pre_ping"] = True  # Verify connections before using
    engine_kwargs["pool_recycle"] = 3600  # Recycle connections after 1 hour
    logger.info(f"Using PostgreSQL database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'configured'}")

# Create engine
engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency for FastAPI routes to get DB session
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database - create all tables
    Call this on application startup
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def check_db_connection():
    """
    Check if database connection is working
    Returns True if connection successful, False otherwise
    """
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection successful")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

