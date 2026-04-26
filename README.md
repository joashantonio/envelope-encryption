# kek-dek-encryption


base_kek (from .env) ──────┐
                            │
                           HMAC
                            │
version string ("v1") ──────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ 32-byte KEK   │  ← derived KEK
                    └───────────────┘


# Instructions on how to run the repository

first run build your own .env file base on the .env.example
```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=kekdek_db
DB_USER="username here"
DB_PASSWORD= "password here"
KEK= "version 0"
```
Make the DB existing in your local kekdek_db 

run the requirements.txt
```
pip install -r requirements.txt
```

after which run the server

```
uvicorn main:app --reload
```

Check out the routes in 
```
localhost:[insertport here]/docs

```
Enjoy
