import hashlib

def generate_sha512_hash(text):
    sha512_hash = hashlib.sha512(text.encode()).hexdigest()
    return sha512_hash

message = "Hello SRM AP"
hash_code = generate_sha512_hash(message)
print("SHA-512 Hash:", hash_code)
