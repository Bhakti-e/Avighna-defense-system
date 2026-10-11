"""Local JWT key loading; never log or provide a signing-key fallback."""
import os
from pathlib import Path
from dotenv import dotenv_values

def load_secret_key():
    path = Path(os.environ.get("AVIGHNA_SECRET_FILE",
                str(Path(__file__).resolve().parents[1] / ".env.auth")))
    key = os.environ.get("SECRET_KEY")
    if key is None:
        key = dotenv_values(path).get("SECRET_KEY") if path.is_file() else None
    if not key or len(key.strip()) < 32 or any(
        marker in key.lower() for marker in ("change", "replace", "your-secret", "your-super")
    ):
        raise RuntimeError(
            "SECRET_KEY is missing or unsafe. Set a random key of at least 32 characters "
            "in the environment or ignored .env.auth; run scripts/setup_local_key.py. "
            "API startup refused."
        )
    return key
