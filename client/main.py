import getpass
from base64 import b16encode, b16decode
from nacl.signing import SigningKey
from nacl.encoding import Base16Encoder
from nacl import pwhash, secret, utils
import requests

def derive_keys(password, salt=None):

    kdf = pwhash.argon2i.kdf
    if salt is None:
        salt = utils.random(pwhash.argon2i.SALTBYTES)
    ops = pwhash.argon2i.OPSLIMIT_INTERACTIVE
    mem = pwhash.argon2i.MEMLIMIT_INTERACTIVE


    seed = kdf(32, password.encode("utf-8"), salt, ops, mem)

    sk = SigningKey(seed)

    return sk.verify_key, sk, salt


def sign_username(sk:SigningKey, username:str):
    signature = sk.sign(username.encode("utf-8"))
    return signature.signature

def sign_nonce(sk:SigningKey, nonce:str):
    signature = sk.sign(b16decode(nonce.encode("utf-8")))
    return signature.signature

def register_account():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    pubkey, seckey, salt = derive_keys(password)
    signature = sign_username(seckey, username)

    json_data = {
        "username": username,
        "public_key": pubkey.encode(encoder=Base16Encoder).decode("utf-8"),
        "salt": b16encode(salt).decode("utf-8"),
        "signature": b16encode(signature).decode("utf-8")
    }

    requests.post("http://localhost:5000/register", json=json_data)


def authenticate_account():

    username = input("Enter username: ")

    r = requests.post("http://localhost:5000/get-challenge", json={"username": username})

    response = r.json()

    nonce = response["nonce"]
    salt = response["salt"]

    password = getpass.getpass("Enter password: ")

    pubkey, seckey, _ = derive_keys(password, salt=b16decode(salt.encode("utf-8")))

    signature = sign_nonce(seckey, nonce)

    request_data = {
        "signature": b16encode(signature).decode("utf-8"),
        "nonce": nonce
    }

    pubkey.verify(b16decode(nonce.encode("utf-8")), signature)

    r = requests.post("http://localhost:5000/authenticate", json=request_data)

    response = r.json()

    print(response)


def main():
    action = input("Enter action: ")

    if action == "register":
        register_account()
    elif action == "authenticate":
        authenticate_account()

if __name__ == "__main__":
    main()