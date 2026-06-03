"""Secret helpers for dojo_epss."""

from __future__ import annotations


class SecretCryptoError(Exception):
    """Raised when DefectDojo secret encryption is unavailable."""


# This function encrypts a secret. This function needs DefectDojo crypto.
def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        from dojo.utils import dojo_crypto_encrypt  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on DefectDojo runtime
        raise SecretCryptoError(
            "DefectDojo encryption helper is unavailable; cannot store the token.",
        ) from exc

    encrypted = dojo_crypto_encrypt(plaintext)
    if not encrypted:
        raise SecretCryptoError("DefectDojo encryption returned an empty value.")
    return str(encrypted)


# This function decrypts a secret. This function needs DefectDojo crypto.
def decrypt_secret(encrypted_value: str) -> str:
    if not encrypted_value:
        return ""
    try:
        from dojo.utils import prepare_for_view  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on DefectDojo runtime
        raise SecretCryptoError(
            "DefectDojo encryption helper is unavailable; cannot read the token.",
        ) from exc

    return str(prepare_for_view(encrypted_value) or "")
