import os
import sys
import psycopg2
from psycopg2 import OperationalError
from dotenv import load_dotenv
from pathlib import Path
import base64

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from helpers.helpers import normalize_parameters
from helpers.constants import *
from core.encryption import *


def get_db_connection():
    load_dotenv()
    try:
        connection = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT"),
        )
        print("Connected to database successfully.")
        return connection
    except OperationalError as error:
        raise RuntimeError(f"Connection failed: {error}") from error


db = get_db_connection()


"""
CORE FUNCTIONS
"""

def insert_new_user(user_data: dict) -> bool:
    # check if data contains all fields
    keys = user_data.keys()
    for k in keys:
        if not k in SENSITIVE_DATA:
            print("Please Supply the required attributes of the user.")
            return False

    # generate new dek for the user
    new_dek = generate_dek()

    # encrypt data of the user using the generated dek
    encrypted_data = {
        "full_name": encrypt_data_with_dek(user_data["full_name"], new_dek),
        "iban": encrypt_data_with_dek(user_data["iban"], new_dek),
        "nin": encrypt_data_with_dek(user_data["nin"], new_dek),
        "phone_number": encrypt_data_with_dek(user_data["phone_number"], new_dek),
        "password": hash_password_sha256(user_data["password"]),
    }

    # encrypt the new dek with kek
    wrapped_new_dek = wrap_dek(new_dek)

    # store new user in the database including his new dek
    with db.cursor() as cursor:
        cursor.execute(
            f"""
            INSERT INTO {TABLE_NAME} (full_name, iban, nin, password, phone_number, dek)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                encrypted_data["full_name"],
                encrypted_data["iban"],
                encrypted_data["nin"],
                encrypted_data["password"],
                encrypted_data["phone_number"],
                wrapped_new_dek,
            )
        )
        db.commit()
        
    return True


def read_user_data(user_id: int, data: list) -> dict:
    encrypted_data = _get_data_from_db(user_id, data)
    user_dek = get_user_dek(user_id)
    unwrapped_dek = unwrap_dek(user_dek)

    decrypted_data = {}
    for key, value in encrypted_data.items():
        decrypted_value = decrypt_data_with_dek(value, unwrapped_dek)
        decrypted_data[key] = decrypted_value.decode("utf-8")
    
    return decrypted_data  


def is_password_match_for_user(user_id: int, password: str)->bool:
    if isinstance(user_id, int) and user_id < 0:
        raise RuntimeError(f"Error password verification for id: {user_id}.")
    if isinstance(user_id, type(None)):
        raise RuntimeError(f"Error password verification for id: None.")

    # retrieve password of user from db
    hashed_password = _get_data_from_db(user_id, ["password"])
    if hashed_password is None:
        raise RuntimeWarning(f"No user found for id: {user_id}.")

    return verify_password_sha256_secure(password, hashed_password["password"])


def rotate_dek_for_all_users()->bool:
    # get all user data
    user_dat = _get_all_user_data()

    try:
        for u in user_dat:
            # get user dek 
            user_dek = unwrap_dek(bytes(u["dek"]))

            # decrypt data
            decrypted_data = {
                "full_name": decrypt_data_with_dek(u["full_name"], user_dek),
                "iban": decrypt_data_with_dek(u["iban"], user_dek),
                "nin": decrypt_data_with_dek(u["nin"], user_dek),
                "phone_number": decrypt_data_with_dek(u["phone_number"], user_dek),
            }

            # generate new dek
            new_dek = generate_dek()

            # encrypt data with new dek
            encrypted_data = {
                "full_name": encrypt_data_with_dek(decrypted_data["full_name"], new_dek),
                "iban": encrypt_data_with_dek(decrypted_data["iban"], new_dek),
                "nin": encrypt_data_with_dek(decrypted_data["nin"], new_dek),
                "phone_number": encrypt_data_with_dek(decrypted_data["phone_number"], new_dek),
                "dek": wrap_dek(new_dek)
            }

            # update user data with new encrypted data and new dek
            if not (_update_user_data(u["id"], encrypted_data, commit=False)):
                print(f'Error: cannot update user id: {u["id"]} on DEK rotation.')
                db.rollback()
                return False

        db.commit()
        return True
    except Exception:
        db.rollback()
        raise


def rotate_kek_for_all_dek():
    try:
        new_kek = rotate_kek()
        
        # get all id and dek from db
        data = get_id_and_dek_for_all_user()
        
        # for each dek, rewrap kek and update dek for each user
        for row_id, wrapped_dek in data:
            new_wrapped_dek = rewrap_dek(bytes(wrapped_dek), new_kek)
            with db.cursor() as cursor:
                cursor.execute(
                    f"UPDATE {TABLE_NAME} SET dek = %s WHERE id = %s;",
                    (psycopg2.Binary(new_wrapped_dek), row_id),)
    except OperationalError as e:
        print(f"KEK rotation failed: {e}")
        return False

    db.commit()
    return True


def rotate_specific_dek(user_id: int)->bool:
    encrypted_data = _get_data_from_db(user_id, ["full_name", "nin", "phone_number", "iban"])
    unwrapped_dek = unwrap_dek(get_user_dek(user_id))

    decrypted_data = {
        "full_name": decrypt_data_with_dek(encrypted_data["full_name"], unwrapped_dek),
        "nin": decrypt_data_with_dek(encrypted_data["nin"], unwrapped_dek),
        "phone_number": decrypt_data_with_dek(encrypted_data["phone_number"], unwrapped_dek),
        "iban": decrypt_data_with_dek(encrypted_data["iban"], unwrapped_dek),
    }

    # create new dek
    new_dek = generate_dek()

    encrypted_data = {
        "full_name": encrypt_data_with_dek(decrypted_data["full_name"], new_dek),
        "nin": encrypt_data_with_dek(decrypted_data["nin"], new_dek),
        "phone_number": encrypt_data_with_dek(decrypted_data["phone_number"], new_dek),
        "iban": encrypt_data_with_dek(decrypted_data["iban"], new_dek),
        "dek": wrap_dek(new_dek)   # add his new dek
    }

    # update the user data and his new dek
    if not (_update_user_data(user_id, encrypted_data, commit=False)):
        print(f'Error: cannot update user id: {user_id} on DEK rotation.')
        db.rollback()
        return False

    db.commit()
    return True


"""
DB HELPER FUNCTIONS
"""

def get_id_and_dek_for_all_user():
    with db.cursor() as c:
        c.execute(f"SELECT id, dek FROM {TABLE_NAME} ORDER BY id;")
        rows = c.fetchall()

    return rows


def get_user_dek(user_id: int)-> bytes:
    with db.cursor() as cursor:
        cursor.execute(
            f"""SELECT dek FROM {TABLE_NAME} WHERE ID = %s""",
            (user_id,)
        )
        user_dek = cursor.fetchone()

    return bytes(user_dek[0])


def _get_data_from_db(user_id, data: list) -> dict:
    if not data:
        print("Please provide data to be retrieved.")
        return None

    data = normalize_parameters(data)
    valid_fields = [field for field in data if field in SENSITIVE_DATA]

    if not valid_fields:
        return None

    columns = ", ".join(valid_fields)
    query = f"SELECT {columns} FROM {TABLE_NAME} WHERE id = %s"

    with db.cursor() as cursor:
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()

    if row:
        return dict(zip(valid_fields, row))

    return None


def _update_user_data(user_id, data: dict, commit: bool = True) -> bool:
    if not data:
        print("Please provide data to be updated.")
        return False

    normalized_keys = normalize_parameters(list(data.keys()))
    valid_fields = {}
    for key in normalized_keys:
        if key in SENSITIVE_DATA or key == "dek":
            valid_fields[key] = data[key]

    if not valid_fields:
        return False

    set_clause = ", ".join(f"{field} = %s" for field in valid_fields.keys())
    values = list(valid_fields.values())
    values.append(user_id)

    query = f"UPDATE {TABLE_NAME} SET {set_clause} WHERE id = %s"

    with db.cursor() as cursor:
        cursor.execute(query, values)
    
    if commit:
        db.commit()

    return True


def _get_all_user_data()->list:
    with db.cursor() as c:
        c.execute(f"SELECT * FROM {TABLE_NAME}")
        rows = c.fetchall()
        columns = [col[0] for col in c.description]
        result = []
        
        for row in rows:
            row_dict = dict(zip(columns, row))
            for key, value in row_dict.items():
                if isinstance(value, (bytes, memoryview)):
                    # Convert memoryview to bytes first, then to base64
                    if isinstance(value, memoryview):
                        value = value.tobytes()
                    row_dict[key] = base64.b64encode(value).decode('utf-8')
            result.append(row_dict)
    
    return result