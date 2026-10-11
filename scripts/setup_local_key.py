"""Generate a local signing key without displaying it. --rotate invalidates sessions."""
import argparse
from pathlib import Path
import os
import secrets

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[1] / ".env.auth"
    if target.exists() and not args.rotate:
        parser.error(".env.auth already exists. Use --rotate only to invalidate existing sessions.")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if args.rotate else os.O_EXCL)
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write("SECRET_KEY=" + secrets.token_urlsafe(64) + "\n")
    print("Local signing key saved in ignored .env.auth. Restart the API; sign in again.")

if __name__ == "__main__":
    main()
