from base64 import b64decode
from typing import Tuple, Any

import nacl.secret
import nacl.utils
from nacl import encoding
from nacl.public import PrivateKey, PublicKey, SealedBox
from passlib.hash import argon2


class Manager:
    def encrypt_data(self, data: bytes, passphrase=None) -> tuple[Any, bytes]:
        if passphrase:
            key = passphrase
        else:
            key: bytes = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        box = nacl.secret.SecretBox(key)
        return (box.encrypt(data), key)

    def decrypt_data(self, enc_data: bytes, key: bytes) -> bytes:
        box = nacl.secret.SecretBox(key)
        return box.decrypt(enc_data)

    def encrypt_key(self, sym_key: bytes, pubkey: PublicKey) -> bytes:
        sealed_box = SealedBox(pubkey)
        return sealed_box.encrypt(sym_key)

    def decrypt_key(self, enc_sym_key: bytes, privkey: PrivateKey) -> bytes:
        sealed_box = SealedBox(privkey)
        return sealed_box.decrypt(enc_sym_key)

    def encrypt(self, data: bytes, pub_key: PublicKey):
        sym_encrypted = self.encrypt_data(data)
        encrypted_key = self.encrypt_key(sym_encrypted[0], pub_key)
        return {"encrypted_key": encrypted_key, "encrypted_data": sym_encrypted[1]}

    def decrypt(self, data: bytes, enc_sym_key: bytes, privkey: PrivateKey) -> bytes:
        plain_key = self.decrypt_key(enc_sym_key, privkey)
        return self.decrypt_data(data, plain_key)

    def prepare_user(self, password: str):
        salt = nacl.utils.random(16)
        hash_list = argon2.using(digest_size=nacl.secret.SecretBox.KEY_SIZE, salt=salt).hash(password).split("$")[1:]

        hash = b64decode(hash_list[4] + "=")

        clear_privkey = PrivateKey.generate()
        pubkey = clear_privkey.public_key

        enc_privkey = self.encrypt_data(bytes(clear_privkey), passphrase=hash)[0]

        return {"salt":salt, "public_key": bytes(pubkey), "encrypted_priv_key": enc_privkey}

    def decrypt_private_key(self, encrypted_priv_key, salt, password):
        hash_list = argon2.using(digest_size=nacl.secret.SecretBox.KEY_SIZE, salt=salt).hash(str(password)).split("$")[1:]
        hash = b64decode(hash_list[4] + "=")

        print(hash)

        return self.decrypt_data(encrypted_priv_key, hash)
