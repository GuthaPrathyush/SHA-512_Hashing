import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

message = "Confidential Message from SRM AP"

parameters = dh.generate_parameters(generator=2, key_size=2048)
alice_private_key = parameters.generate_private_key()
bob_private_key = parameters.generate_private_key()

alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

alice_shared_key = alice_private_key.exchange(bob_public_key)
bob_shared_key = bob_private_key.exchange(alice_public_key)

assert alice_shared_key == bob_shared_key, "Key exchange failed!"

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"Diffie-Hellman-AES",
).derive(alice_shared_key)

hash_code = hashlib.sha512(message.encode()).hexdigest()

message_with_hash = (message + hash_code).encode()

padded_message = message_with_hash + b" " * (16 - len(message_with_hash) % 16)

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()

print("Encrypted Message:", ciphertext.hex())


decryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

decrypted_message_with_hash = decrypted_padded.strip().decode()

received_message = decrypted_message_with_hash[:-128]
received_hash = decrypted_message_with_hash[-128:]

computed_hash = hashlib.sha512(received_message.encode()).hexdigest()

if computed_hash == received_hash:
    print("Integrity Verified! Message:", received_message)
else:
    print("Integrity Check Failed!")
