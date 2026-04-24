def normalize_parameters(data: list):
    for i, d in enumerate(data):
        d_lower = d.lower() if isinstance(d, str) else d
        
        match d_lower:
            # full name
            case "full name" | "fullname" | "name" | "full_name" | "fullName" | "FullName" | "Full Name":
                data[i] = "full_name"
            
            # iban
            case "iban" | "iban_number" | "iban_no" | "international_bank_account_number" | "bank_account_iban" | "account_iban":
                data[i] = "iban"
            
            # nin
            case "nin" | "nin_number" | "national_id" | "national_identification_number" | "national_id_number" | "nid" | "national_insurance_number" | "social_security_number":
                data[i] = "nin"
            
            # phone_number
            case "phone_number" | "phone" | "phonenumber" | "phone_no" | "mobile" | "mobile_number" | "cell" | "cellphone" | "telephone" | "tel" | "contact_number":
                data[i] = "phone_number"
            
            case _:
                data[i] = d
    
    return data


def to_bytes(value)->bytes:
    if isinstance(value, bytes):
        return value
    
    return str(value).encode("utf-8")