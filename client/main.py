import getpass
import requests
import hashlib

from base64 import b16encode, b16decode

from nacl.signing import SigningKey
from nacl.public import SealedBox
from nacl.encoding import Base16Encoder
from nacl import pwhash, secret, utils


bearer_token = ""

def evaluate_password(password):
    hasher = hashlib.sha1()
    hasher.update(password.encode("utf-8"))
    hex_digest = hasher.hexdigest()

    r = requests.get(f"https://api.pwnedpasswords.com/range/{hex_digest[:5]}")
    data_lines = r.content.decode("utf-8").split("\r\n")
    data_lines = set(map(lambda x: x.split(":")[0], data_lines))

    if hex_digest.upper()[5:] in data_lines:
        print("Password found in public password lists. Please pick a new password")
        return False
    return True

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
    while not evaluate_password(password):
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

    encrypted_nonce = response["encrypted_nonce"]
    salt = response["salt"]

    password = getpass.getpass("Enter password: ")

    pubkey, seckey, _ = derive_keys(password, salt=b16decode(salt.encode("utf-8")))


    nonce = SealedBox(seckey.to_curve25519_private_key()).decrypt(encrypted_nonce.encode("utf-8"), encoder=Base16Encoder)
    nonce = b16encode(nonce).decode("utf-8")

    signature = sign_nonce(seckey, nonce)

    request_data = {
        "signature": b16encode(signature).decode("utf-8"),
        "nonce": nonce
    }

    pubkey.verify(b16decode(nonce.encode("utf-8")), signature)

    r = requests.post("http://localhost:5000/authenticate", json=request_data)

    response = r.json()

    if r.ok:
        global bearer_token
        bearer_token = response["auth_token"]
        print("Authenticated Successfully")
    else:
        print("Failed Authentication")

def check_auth():
    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }

    response = requests.get("http://localhost:5000/check-auth", headers=headers)

    print(response.json()["result"])


def main():

    while True:
        action = input("Enter action: ")
        if action == "register":
            register_account()
        elif action == "authenticate":
            authenticate_account()
        elif action == "check":
            check_auth()
        elif action == "quit" or action == "exit":
            exit()

if __name__ == "__main__":
    main()