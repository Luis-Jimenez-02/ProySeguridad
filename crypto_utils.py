from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key(key, filename, is_private=False):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_key(filename, is_private=False):
    with open(filename, 'rb') as f:
        key_data = f.read()
    if is_private:
        return serialization.load_pem_private_key(key_data, password=None)
    else:
        return serialization.load_pem_public_key(key_data)

def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def hash_sha384(data):
    digest = hashes.Hash(hashes.SHA384())
    digest.update(data)
    return digest.finalize()

def hash_sha512(data):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()

def hash_blake2b(data):
    return hashlib.blake2b(data).digest()

def load_key_from_data(key_data, is_private=False):
    if is_private:
        return serialization.load_pem_private_key(key_data, password=None)
    else:
        return serialization.load_pem_public_key(key_data)
