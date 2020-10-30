from app import app, jwt_signing_key
from flask import request

import base64
import sqlite3
import time

from nacl.signing import VerifyKey
from nacl import utils
from nacl.encoding import Base16Encoder
from nacl.exceptions import BadSignatureError

from jwcrypto import jwt


live_challenges = {}

def verify_signature(public_key:str, signature:str, username:str):
    vk = VerifyKey(public_key.encode("utf-8"), encoder=Base16Encoder)
    raw_signature = base64.b16decode(signature.encode("utf-8"))
    
    try:
        vk.verify(username.encode("utf-8"), raw_signature)
    except BadSignatureError:
        return False
    return True

@app.route("/")
def index():
    return {"endpoint": "auth-api"}


@app.route("/register", methods=["POST"])
def register():
    try:
        r = request.json

        username = r["username"]
        public_key = r["public_key"]
        salt = r["salt"]
        signature = r["signature"]

    except:
        return {"result": "error", "http code": 400}, 400

    verified = verify_signature(public_key, signature, username)

    if verified is False:
        return {"result": "error", "http code": 403}, 403

    try:
        conn = sqlite3.connect("/app/app.db")
        cursor = conn.cursor()

        cursor.execute("INSERT INTO accounts(username, pubkey_hex, salt) VALUES(?,?,?);", (username, public_key, salt))

        conn.commit()
    except sqlite3.IntegrityError:
        return {"result": "error", "http code": 409}, 409

    return "", 204


@app.route("/get-challenge", methods=["POST"])
def get_challenge():
    try:
        r = request.json
        username = r["username"]
    except:
        return {"result": "error", "http code": 400}, 400

    try:
        conn = sqlite3.connect("/app/app.db")
        cursor = conn.cursor()

        cursor.execute("SELECT pubkey_hex, salt FROM accounts WHERE username=? LIMIT 1;", [username])

        results = cursor.fetchone()

        conn.commit()
    except sqlite3.OperationalError:
        return {"result": "error", "http code": 404}, 404

    pubkey_hex = results[0]
    salt = results[1]

    nonce = utils.random(32)

    response = {
        "nonce": base64.b16encode(nonce).decode("utf-8"),
        "salt": salt
    }

    global live_challenges
    live_challenges[base64.b16encode(nonce).decode("utf-8")] = (username, pubkey_hex)

    return response

@app.route("/authenticate", methods=["POST"])
def authenticate():
    try:
        r = request.json
        signature = r["signature"]
        nonce = r["nonce"]
    except:
        return {"result": "error", "http code": 400}, 400

    global live_challenges
    
    try:
        challenge_data = live_challenges[nonce]
        username = challenge_data[0]
        pubkey_hex = challenge_data[1]
    except:
        return {"result": "error", "http code": 401, "here": 1}, 401

    # irrespective of if we succeed or fail always delete the current challenge
    # this forces clients to generate a new challenge for each auth attempt
    del live_challenges[nonce]

    print(f"pubkey_hex = {pubkey_hex}")

    try:
        vk = VerifyKey(pubkey_hex.encode("utf-8"), encoder=Base16Encoder)
        vk.verify(smessage=base64.b16decode(nonce.encode("utf-8")), signature=base64.b16encode(signature.encode("utf-8")))
    except BadSignatureError:
        return {"result": "error", "http code": 401, "here": 2}, 401

    expire_time = time.time() + 600
    issued_at = time.time()

    new_jwt = jwt.JWT(
        header={
            "alg": "EdDSA"},
        claims={
            "username": username,
            "exp": expire_time,
            "iat": issued_at}
    )

    new_jwt.make_signed_token(jwt_signing_key)

    return {"auth_token": new_jwt.serialize(), "expires": expire_time, "issued_at": issued_at}