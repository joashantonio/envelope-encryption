from pydantic import BaseModel


from core.database import read_user_data,_get_all_user_data
from fastapi import FastAPI
from core.encryption import generate_dek, encrypt_data_with_dek, decrypt_data_with_dek, wrap_dek, unwrap_dek
from core.kms import get_kek_state, rotate_kek,_derive_kek
from helpers.constants import SENSITIVE_DATA, NONCE_SIZE
from helpers.helpers import normalize_parameters, to_bytes
from core import encryption, kms
from helpers import constants, helpers
from tests.database_test  import read_user_data_test, insert_new_user_test, password_test, rotate_dek_for_all_users_test,rotate_kek_test,rotate_specific_dek_test

# for get_database_data 
class GetDatabaseDataRequest(BaseModel):
    user_id: int
    data: list




app = FastAPI()



@app.get("/")
def root():
    return {"message": "Testing KEK and DEK encryption/decryption"}\
        
        
@app.get("/get_kek_state")
def get_kek_state_endpoint():
    kek_state = get_kek_state()
    return {"result": kek_state}

@app.get("/derive_kek")
def derive_kek_endpoint(string: str):
    kek_state = _derive_kek(string)
    kek_hex = kek_state.hex()
    return {"result": kek_hex}

@app.get("/get_all_user_data_encrypted")
def get_all_user():
    response = _get_all_user_data()
    return {"result": response}

# gi post kay taas kaayo ang params if e complete
@app.post("/get_row_database_data")
def get_database_data(request: GetDatabaseDataRequest):
    response =  read_user_data(request.user_id, request.data)
    return {"result": response}

@app.post("/insert_new_user")
def insert_new_user():
    response = insert_new_user_test()
    return {"result": response}

