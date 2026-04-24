from pathlib import Path
import sys

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.kms import *

TABLE_NAME = "user_data"
SENSITIVE_DATA = ["full_name", "iban", "nin", "phone_number", "password"]
NONCE_SIZE = 12
HASH_ITERATIONS = 100000
VERSION_SIZE = len(get_kek_state().encode("utf-8"))