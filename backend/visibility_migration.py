"""Additive SQLite migration; never infer heartbeat history from last_seen."""
from sqlalchemy import inspect

VISIBILITY_COLUMNS = {
    "last_network_seen": "DATETIME",
    "last_agent_heartbeat": "DATETIME",
    "last_endpoint_event": "DATETIME",
    "agent_health_state": "VARCHAR(20)",
}

def migrate_visibility_columns(engine):
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Visibility migration is validated for SQLite only.")
    with engine.begin() as connection:
        existing = {column["name"] for column in inspect(connection).get_columns("devices")}
        for name, sql_type in VISIBILITY_COLUMNS.items():
            if name not in existing:
                connection.exec_driver_sql(f"ALTER TABLE devices ADD COLUMN {name} {sql_type}")
        if inspect(connection).has_table("alerts"):
            columns = {c["name"] for c in inspect(connection).get_columns("alerts")}
            if "visibility_event_key" not in columns:
                connection.exec_driver_sql("ALTER TABLE alerts ADD COLUMN visibility_event_key VARCHAR(512)")
            connection.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_visibility_event ON alerts (visibility_event_key)"
            )
