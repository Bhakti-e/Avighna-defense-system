"""Additive SQLite migration; never infer heartbeat history from last_seen."""
from sqlalchemy import inspect

VISIBILITY_COLUMNS = {
    "last_network_seen": "DATETIME",
    "last_agent_heartbeat": "DATETIME",
    "last_endpoint_event": "DATETIME",
}

def migrate_visibility_columns(engine):
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Visibility migration is validated for SQLite only.")
    with engine.begin() as connection:
        existing = {column["name"] for column in inspect(connection).get_columns("devices")}
        for name, sql_type in VISIBILITY_COLUMNS.items():
            if name not in existing:
                connection.exec_driver_sql(f"ALTER TABLE devices ADD COLUMN {name} {sql_type}")
