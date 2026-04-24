from pathlib import Path
import sys

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.database import *


def insert_new_user_test():
    if insert_new_user({
        "full_name": "sam",
        "iban": "123",
        "nin": "321",
        "phone_number" : "231", 
        "password": "password"
    }):
        print("[PASSED] insert_new_user_test.")
    else:
        print("[FAILED] insert_new_user_test")


def read_user_data_test():
    read_user_data(
        1,
        ["fullname",
          "iban",
          "nin"]
    )


def password_test():
    if(is_password_match_for_user(1, "password")):
        print("[PASSED] password_test.")
    else:
        print("[FAILED] password_test.")


def rotate_dek_for_all_users_test():
    if(rotate_dek_for_all_users()):
        print("[PASSED] rotate_dek_for_all_users_test.")
    else:
        print("[FAILED] rotate_dek_for_all_users_test.")


def rotate_kek_test():
    if(rotate_kek_for_all_dek()):
        print("[PASSED] rotate_kek_test.")
    else:
        print("[FAILED] rotate_kek_test.")


def rotate_specific_dek_test():
    if(rotate_specific_dek(1)):
        print("[PASSED] rotate_specific_dek_test.")
    else:
        print("[FAILED] rotate_specific_dek_test.")

