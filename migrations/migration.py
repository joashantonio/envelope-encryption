import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "user": "postgres",
    "password": "22101163",
}

DATABASE_NAME = "kekdek_db"


def create_database():
    """Create the database if it doesn't exist."""
    conn = psycopg2.connect(**DB_CONFIG, dbname="postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (DATABASE_NAME,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DATABASE_NAME)))
        print(f"[+] Database '{DATABASE_NAME}' created successfully.")
    else:
        print(f"[~] Database '{DATABASE_NAME}' already exists. Skipping.")

    cursor.close()
    conn.close()


def run_migration():
    """Run the migration to create the user_data table."""
    conn = psycopg2.connect(**DB_CONFIG, dbname=DATABASE_NAME)
    cursor = conn.cursor()

    create_table_query = """
        CREATE TABLE IF NOT EXISTS user_data (
            id           SERIAL PRIMARY KEY,
            full_name    TEXT   NOT NULL,
            iban         TEXT   NOT NULL,
            nin          TEXT   NOT NULL,
            password     TEXT   NOT NULL,
            phone_number TEXT   NOT NULL,
            dek          BYTEA  NOT NULL
        );
    """

    cursor.execute(create_table_query)
    conn.commit()
    print("[+] Migration complete: table 'user_data' is ready.")

    cursor.close()
    conn.close()


def rollback_migration():
    """Drop the user_data table (rollback)."""
    conn = psycopg2.connect(**DB_CONFIG, dbname=DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS user_data;")
    conn.commit()
    print("[-] Rollback complete: table 'user_data' dropped.")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    import sys

    command = sys.argv[1] if len(sys.argv) > 1 else "migrate"

    if command == "migrate":
        create_database()
        run_migration()
    elif command == "rollback":
        rollback_migration()
    else:
        print("Usage: python migration.py [migrate|rollback]")
