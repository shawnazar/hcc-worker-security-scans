"""Laravel-compatible encryption/decryption."""

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class LaravelDecryptor:
    """Decrypt data encrypted by Laravel's encryption system.

    Laravel uses AES-256-CBC encryption with the following format:
    - Base64 encoded JSON containing: {"iv": "...", "value": "...", "mac": "..."}
    - The key is the APP_KEY (after removing "base64:" prefix and decoding)
    """

    def __init__(self, app_key: str):
        """Initialize the decryptor with Laravel's APP_KEY.

        Args:
            app_key: Laravel's APP_KEY (including the "base64:" prefix)
        """
        # Laravel key is base64 encoded after "base64:" prefix
        if app_key.startswith("base64:"):
            app_key = app_key[7:]
        self.key = base64.b64decode(app_key)

    def decrypt(self, payload: str) -> Any:
        """Decrypt a Laravel encrypted value.

        Args:
            payload: The encrypted payload (base64 encoded JSON)

        Returns:
            The decrypted value (parsed from JSON if applicable)

        Raises:
            ValueError: If the MAC verification fails or decryption fails
        """
        # Decode the outer base64 layer
        try:
            data = json.loads(base64.b64decode(payload))
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Invalid encrypted payload format: {e}") from e

        # Extract components
        iv = base64.b64decode(data["iv"])
        encrypted_value = base64.b64decode(data["value"])
        mac = data["mac"]

        # Verify MAC
        expected_mac = hmac.new(
            self.key,
            (data["iv"] + data["value"]).encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed - data may be corrupted")

        # Decrypt using AES-256-CBC
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_value) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]

        # Parse as JSON (Laravel serializes data as JSON before encryption)
        try:
            return json.loads(decrypted.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # If not valid JSON, return as string
            return decrypted.decode("utf-8")
