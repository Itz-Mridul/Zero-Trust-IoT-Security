# Data Directory

This directory stores runtime data files:
- `security.db` — main SQLite database (auto-created by `iot_server.py`)
- `attack_data.db` — synthetic attack data (created by `generate_attack_data.py`)
- `training_data.db` — merged ML training data (created by `merge_training_data.py`)

These files are **not committed to Git** (see `.gitignore`).
