from pathlib import Path
import os

import psycopg2


DEFAULT_PORT = "5432"


def load_env_local(env_paths):
    loaded_values = {}

    for env_path in env_paths:
        env_path = Path(env_path)
        if not env_path.exists():
            continue

        with open(env_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                loaded_values[key.strip()] = value.strip().strip('"').strip("'")

    for key, value in loaded_values.items():
        os.environ.setdefault(key, value)


def get_db_config(env_paths=None):
    if env_paths:
        load_env_local(env_paths)

    config = {
        "host": os.environ.get("PGHOST", "").strip(),
        "port": os.environ.get("PGPORT", DEFAULT_PORT).strip(),
        "dbname": os.environ.get("PGDATABASE", "").strip(),
        "user": os.environ.get("PGUSER", "").strip(),
        "password": os.environ.get("PGPASSWORD", os.environ.get("PGPASS", "")).strip(),
    }

    missing_keys = [
        env_name
        for env_name, value in {
            "PGHOST": config["host"],
            "PGDATABASE": config["dbname"],
            "PGUSER": config["user"],
            "PGPASSWORD ou PGPASS": config["password"],
        }.items()
        if not value
    ]
    if missing_keys:
        raise RuntimeError(
            "Configuração do PostgreSQL incompleta. Defina as variáveis: "
            + ", ".join(missing_keys)
        )

    return config


def connect_postgres(env_paths=None, **overrides):
    config = get_db_config(env_paths=env_paths)
    config.update({key: value for key, value in overrides.items() if value is not None})
    return psycopg2.connect(**config)
