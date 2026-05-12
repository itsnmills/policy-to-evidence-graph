from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None


_SALT_BYTES = 16
_NONCE_BYTES = 12
_PBKDF2_ITERS = 220_000
_AAD = b"policy-to-evidence-graph:v1"


class EncryptionError(RuntimeError):
    """Raised when encryption cannot run because dependency/state is invalid."""


def ensure_crypto_available() -> None:
    if AESGCM is None:
        raise EncryptionError(
            "Encryption requires the 'cryptography' package. Install it with `pip install cryptography`."
        )


@dataclass(frozen=True)
class SecurityResult:
    encrypted: Path
    source: Path
    sha256: str


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        _PBKDF2_ITERS,
        dklen=32,
    )


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(obj: object) -> str:
    return __import__("json").dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ensure_file_private(path: Path) -> None:
    stat = path.stat()
    if stat.st_mode & 0o077:
        raise EncryptionError(
            f"Passphrase file permissions are too open: {path}. Set chmod 600 and owner-only access."
        )


def compute_payload_signature(payload: Mapping[str, object]) -> str:
    sanitized: Dict[str, object] = dict(payload)
    if "integrity" in sanitized:
        sanitized.pop("integrity", None)
    return hashlib.sha256(_canonical(sanitized).encode("utf-8")).hexdigest()


def _manifest_entry(path: Path) -> Dict[str, object]:
    stat = path.stat()
    return {
        "sha256": hash_file(path),
        "bytes": stat.st_size,
        "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
    }


def verify_payload_signature(payload: Mapping[str, object], signature: str) -> bool:
    return compute_payload_signature(payload) == signature


def _validate_passphrase(passphrase: str) -> None:
    if not passphrase or len(passphrase.strip()) < 24:
        raise EncryptionError("Passphrase must be at least 24 characters.")


def resolve_passphrase(env_var: str) -> Optional[str]:
    if not env_var:
        return None
    return os.getenv(env_var)


def encrypt_payload(payload: bytes | str, passphrase: str) -> bytes:
    ensure_crypto_available()
    _validate_passphrase(passphrase)

    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    token = AESGCM(key).encrypt(nonce, payload, _AAD)  # type: ignore[union-attr]
    blob = salt + nonce + token
    return base64.urlsafe_b64encode(blob)


def decrypt_payload(encrypted_payload: bytes | str, passphrase: str) -> bytes:
    ensure_crypto_available()
    _validate_passphrase(passphrase)

    if isinstance(encrypted_payload, str):
        encrypted_payload = encrypted_payload.encode("utf-8")

    try:
        blob = base64.urlsafe_b64decode(encrypted_payload)
    except Exception as exc:
        raise EncryptionError("Invalid encrypted payload format.") from exc
    if len(blob) < (_SALT_BYTES + _NONCE_BYTES + 16):
        raise EncryptionError("Encrypted payload is too short.")

    salt = blob[:_SALT_BYTES]
    nonce = blob[_SALT_BYTES : _SALT_BYTES + _NONCE_BYTES]
    token = blob[_SALT_BYTES + _NONCE_BYTES :]

    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, token, _AAD)  # type: ignore[union-attr]
    except Exception as exc:
        raise EncryptionError("Decryption failed. Check passphrase and input file.") from exc


def encrypt_file(source: Path, destination: Path, passphrase: str) -> SecurityResult:
    encrypted = encrypt_payload(source.read_bytes(), passphrase)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encrypted)
    destination.chmod(0o600)
    return SecurityResult(encrypted=destination, source=source, sha256=hash_file(source))


def decrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    payload = source.read_bytes()
    plain = decrypt_payload(payload, passphrase)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plain)
    destination.chmod(0o600)


def build_integrity_manifest(file_paths: Mapping[str, Path]) -> Dict[str, object]:
    manifest: Dict[str, str] = {}
    for label, path in file_paths.items():
        if not path.exists() or not path.is_file():
            continue
        manifest[label] = _manifest_entry(path)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "file_count": len(manifest),
        "files": manifest,
    }


def write_integrity_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        __import__("json").dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def verify_file_integrity(manifest: Mapping[str, object], base_dir: Optional[Path] = None) -> tuple[bool, list[str]]:
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        return False, ["Manifest format invalid: files is not an object"]

    base = base_dir or Path(".")
    failures: list[str] = []
    for label, entry in files.items():
        if not isinstance(label, str):
            failures.append(f"Invalid manifest entry label: {label}")
            continue
        candidate = Path(label)
        if not candidate.is_absolute():
            candidate = base / candidate
        if not candidate.exists():
            failures.append(f"Missing file: {candidate}")
            continue

        expected = None
        if isinstance(entry, str):
            expected = entry
        elif isinstance(entry, dict):
            expected = str(entry.get("sha256", "") or "")
        else:
            failures.append(f"Invalid manifest entry type for {label}: {type(entry)}")
            continue

        if not expected:
            continue
        actual = hash_file(candidate)
        if actual != expected:
            failures.append(f"Integrity mismatch for {candidate.name}")

    return len(failures) == 0, failures


def resolve_passphrase(env_name: str, passphrase_file: Optional[str] = None) -> Optional[str]:
    if passphrase_file:
        file_path = Path(passphrase_file).expanduser()
        if not file_path.exists():
            raise EncryptionError(f"Passphrase file not found: {file_path}")
        _ensure_file_private(file_path)
        value = file_path.read_text(encoding="utf-8").strip()
        if value:
            return value

    if not env_name:
        return None

    env_value = os.getenv(env_name)
    if env_value:
        env_value = env_value.strip()
        if env_value.startswith("file://"):
            file_path = Path(env_value.removeprefix("file://")).expanduser()
            if not file_path.exists():
                raise EncryptionError(f"Passphrase file not found from env: {file_path}")
            _ensure_file_private(file_path)
            value = file_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        return env_value
    return None


def verify_snapshot_chain(snapshot_payload: Mapping[str, object], previous_payload: Optional[Mapping[str, object]] = None) -> list[str]:
    if not isinstance(snapshot_payload, dict):
        return ["Snapshot payload invalid"]

    integrity = snapshot_payload.get("integrity", {})
    if not isinstance(integrity, dict):
        return ["Snapshot missing integrity metadata"]

    current_signature = compute_payload_signature(snapshot_payload)
    if integrity.get("snapshot_signature") != current_signature:
        return [
            "Snapshot signature mismatch: manifest was modified outside the normal write path",
        ]

    previous_signature = None
    if previous_payload:
        previous_signature = (
            previous_payload.get("integrity", {}).get("snapshot_signature")
            if isinstance(previous_payload.get("integrity", {}), dict)
            else None
        )

    expected_chain = hashlib.sha256(
        f"{previous_signature or ''}:{current_signature}".encode("utf-8")
    ).hexdigest()
    if integrity.get("snapshot_chain_signature") and integrity.get("snapshot_chain_signature") != expected_chain:
        if previous_signature:
            return [
                "Snapshot chain signature mismatch. This indicates a gap in review history or tampering.",
            ]
    return []
