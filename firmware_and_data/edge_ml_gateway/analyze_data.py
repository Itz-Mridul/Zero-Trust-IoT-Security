"""
analyze_data.py — IoT Heartbeat Data Analyser

Reads the local iot_data.db (produced by iot_server.py) and prints
per-device Inter-Packet Delay (IPD) statistics.

Run: python3 analyze_data.py
"""

import sqlite3
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# PATH RESOLUTION
# Priority 1: same folder as this script (Pi or any machine)
# Priority 2: explicit override via env var ANALYZE_DB_PATH
# ---------------------------------------------------------------------------
import os

_script_dir = Path(__file__).resolve().parent
_env_path   = os.environ.get("ANALYZE_DB_PATH")

if _env_path:
    DB_PATH = Path(_env_path)
else:
    DB_PATH = _script_dir / "iot_data.db"


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    result = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return result is not None


# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
def main() -> None:
    print(f"[Analyser] Database : {DB_PATH.resolve()}")

    if not DB_PATH.exists():
        print(
            "❌  Database file not found.\n"
            "    Make sure iot_server.py has run and recorded some heartbeats.\n"
            f"    Expected path: {DB_PATH.resolve()}"
        )
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        if not table_exists(conn, "heartbeats"):
            print(
                "❌  Table 'heartbeats' does not exist yet.\n"
                "    Start iot_server.py so it can initialise the database."
            )
            return

        df = pd.read_sql_query("SELECT * FROM heartbeats", conn)
    finally:
        conn.close()

    # --- Volume check ---
    total = len(df)
    if total == 0:
        print("⚠️  Database is empty. Is iot_server.py running and receiving data?")
        return

    print(f"[Analyser] Rows loaded: {total}")

    # --- Type coercion & error tracking ---
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["rssi"]      = pd.to_numeric(df["rssi"],      errors="coerce")

    bad_ts = df["timestamp"].isna().sum()
    if bad_ts:
        print(f"⚠️  {bad_ts} rows had invalid timestamps and will be ignored.")

    df = df.dropna(subset=["device_id", "timestamp"])

    # --- Logic check ---
    unique_devices = df["device_id"].nunique()
    if total < 2 or unique_devices == total:
        print(
            f"⚠️  Insufficient data: {total} rows / {unique_devices} unique device IDs.\n"
            "    Need multiple packets from the SAME device_id to calculate IPD.\n"
            f"    Sample IDs: {list(df['device_id'].unique()[:5])}"
        )
        return

    # --- IPD calculation ---
    df = df.sort_values(["device_id", "timestamp"])
    df["ipd"] = df.groupby("device_id")["timestamp"].diff()
    ipd_df = df.dropna(subset=["ipd"])

    if ipd_df.empty:
        print(
            f"⚠️  {len(df)} rows loaded but IPD could not be calculated.\n"
            "    Need 2+ consecutive rows with the same device_id.\n"
            f"    Device IDs in DB: {list(df['device_id'].unique())}"
        )
        return

    # --- Summary report ---
    print(f"\n✅  Analysis complete — {len(ipd_df)} IPD samples across {unique_devices} device(s).")
    print("-" * 60)

    summary = (
        ipd_df
        .groupby("device_id")["ipd"]
        .agg(count="count", mean="mean", std="std", min="min", max="max")
    )
    # Convert seconds → milliseconds for readability
    summary = summary * 1000
    summary.columns = ["count", "mean_ms", "std_ms", "min_ms", "max_ms"]

    print(summary.to_string(float_format=lambda v: f"{v:.3f}"))
    print()

    # RSSI summary if available
    rssi_valid = df["rssi"].dropna()
    if not rssi_valid.empty:
        print(f"📶  RSSI stats (dBm) — mean: {rssi_valid.mean():.1f}  "
              f"min: {rssi_valid.min():.0f}  max: {rssi_valid.max():.0f}")


if __name__ == "__main__":
    main()
