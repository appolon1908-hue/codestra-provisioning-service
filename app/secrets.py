import os
from pathlib import Path


class SecretReferenceError(RuntimeError):
    pass


def read_secret_file(path_value: str, *, allow_public: bool = False) -> str:
    path = Path(path_value)
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file():
            raise SecretReferenceError("invalid_secret_reference")
        permitted = 0o644 if allow_public else 0o600
        if metadata.st_mode & 0o777 & ~permitted:
            raise SecretReferenceError("secret_permissions_too_broad")
        value = path.read_text().strip()
    except OSError as exc:
        raise SecretReferenceError("secret_reference_unreadable") from exc
    if not value:
        raise SecretReferenceError("secret_reference_empty")
    return value


def read_secret_reference(variable: str, required: bool = True) -> str | None:
    reference = os.getenv(variable)
    if not reference:
        if required:
            raise SecretReferenceError(f"{variable.lower()}_not_configured")
        return None
    return read_secret_file(reference)
