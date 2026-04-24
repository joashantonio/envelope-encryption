import ast
import base64
import binascii
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from helpers.constants import *
from helpers.helpers import *
from core.kms import *


def generate_dek():
    return secrets.token_bytes(32) # 256 bit


def encrypt_data_with_dek(data, dek: bytes) -> bytes:
    payload = to_bytes(data)

    nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted_data = AESGCM(dek).encrypt(nonce, payload, None)
    return base64.b64encode(nonce + encrypted_data).decode("ascii")


def decrypt_data_with_dek(data, dek: bytes) -> bytes:
    if isinstance(data, memoryview):
        data = data.tobytes()

    if isinstance(data, str):
        try:
            data = base64.b64decode(data.encode("ascii"), validate=True)
        except (binascii.Error, ValueError):
            # Support legacy rows stored as str(bytes), e.g. "b'...'"
            parsed = ast.literal_eval(data)
            if not isinstance(parsed, bytes):
                raise TypeError("Encrypted payload must decode to bytes.")
            data = parsed

    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    return AESGCM(dek).decrypt(nonce, ciphertext, None)


def hash_password_sha256(password: str) -> str:
    # The salt ensures that even identical passwords produce different hashes
    salt = secrets.token_bytes(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
    # Store salt + hash together as hex
    return (salt + pwdhash).hex()


def verify_password_sha256_secure(password: str, stored_hash: str) -> bool:
    decoded = bytes.fromhex(stored_hash)
    salt = decoded[:16] # Extract the salt (first 16 bytes)
    stored_pwdhash = decoded[16:] # Extract the hash (remaining bytes)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
    return pwdhash == stored_pwdhash


def wrap_dek(dek: bytes, kek_version: str | None = None) -> bytes:
    version = kek_version or get_kek_state()
    kek = get_kek(version)

    nonce = secrets.token_bytes(NONCE_SIZE)
    wrapped = AESGCM(kek).encrypt(nonce, dek, None)
    payload = base64.b64encode(nonce + wrapped).decode("ascii")
    return f"{version}:{payload}".encode("utf-8")


def unwrap_dek(wrapped_dek: bytes) -> bytes:
    decoded = wrapped_dek.decode("utf-8")
    version, encoded_payload = decoded.split(":", 1)
    payload = base64.b64decode(encoded_payload.encode("ascii"))
    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    kek = get_kek(version)
    return AESGCM(kek).decrypt(nonce, ciphertext, None)


def rewrap_dek(wrapped_dek: bytes, kek_version: str | None = None) -> bytes:
    unwrapped_dek = unwrap_dek(wrapped_dek)
    
    if kek_version == None:
        return wrap_dek(unwrapped_dek, get_kek_state())
    
    return wrap_dek(unwrapped_dek, kek_version)