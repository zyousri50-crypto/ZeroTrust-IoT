from pathlib import Path
from secrets import token_urlsafe
from getpass import getpass
from tempfile import NamedTemporaryFile
from werkzeug.security import generate_password_hash

INSTANCE = Path(__file__).resolve().parent / "dashboard" / "instance"
SECRET = INSTANCE / "secret_key"
PASSWORD = INSTANCE / "admin_password.hash"


def write_private_file(path, content):
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=INSTANCE,
        prefix=".setup-",
        delete=False,
    ) as temp:
        temp_path = Path(temp.name)
        temp_path.chmod(0o600)
        temp.write(content)

    try:
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)


def main():
    INSTANCE.mkdir(parents=True, exist_ok=True)
    INSTANCE.chmod(0o700)

    if SECRET.exists() or PASSWORD.exists():
        raise SystemExit(
            "Authentication files already exist. "
            "Existing credentials were not changed."
        )

    password = getpass("New admin password: ")
    confirm = getpass("Confirm password: ")

    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")

    if password != confirm:
        raise SystemExit("Passwords do not match.")

    try:
        write_private_file(SECRET, token_urlsafe(48))
        write_private_file(PASSWORD, generate_password_hash(password))
    except Exception:
        SECRET.unlink(missing_ok=True)
        PASSWORD.unlink(missing_ok=True)
        raise

    print("Admin authentication configured successfully.")
    print("Username: admin")


if __name__ == "__main__":
    main()
