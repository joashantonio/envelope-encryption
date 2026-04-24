import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from dotenv import load_dotenv

core_dir = Path(__file__).parent
project_root_dir = core_dir.parent
load_dotenv()


_STATE = project_root_dir / "kek_state.json"


def _load_base_kek():
    base_kek = os.getenv("KEK")

    if not base_kek:
        raise RuntimeError("KEK is missing from the environment.")
    
    return base64.b64decode(base_kek)


def get_kek_state()->str:
    with _STATE.open("r", encoding="utf-8") as state_file:
        return json.load(state_file)["current_version"]


def _derive_kek(version: str) -> bytes:
    base_kek = _load_base_kek()
    return hmac.new(base_kek, version.encode("utf-8"), hashlib.sha256).digest()


def _save_state(state: dict) -> None:
    with _STATE.open("w", encoding="utf-8") as state_file:
        json.dump(state, state_file, indent=2)


def get_kek(version: str | None = None) -> bytes:
    if version == None:
        version = get_kek_state()

    return _derive_kek(version)


def rotate_kek() -> str:
    current_version = get_kek_state()
    next_version = determine_next_kek_version(current_version)
    _save_state({"current_version": next_version})
    return next_version


def determine_next_kek_version(version: str) -> str:
    return version[:1] + str(int(version[1:]) + 1)