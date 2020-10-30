from flask import Flask
from jwcrypto import jwk
import logging
import sqlite3

app = Flask(__name__)


def setup_database():
    # Create an in memory database to store accounts and public keys
    conn = sqlite3.connect("/app/app.db")

    cursor = conn.cursor()

    cursor.execute("CREATE TABLE accounts(username VARCHAR(40) PRIMARY KEY, pubkey_hex CHAR(64) UNIQUE, salt CHAR(32) UNIQUE)")

    cursor.close()

    conn.commit()
    conn.close()
setup_database()


jwt_signing_key = jwk.JWK.generate(kty="OKP", crv="Ed448")

from app import routes