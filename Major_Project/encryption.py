import hashlib

# Define your encryption keyword here
ENCRYPTION_KEYWORD = "your_secret_keyword"

# Password encryption function (SHA256 + keyword)
def encrypt_password(password):
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    encrypted_password = hashlib.sha256((sha_signature + ENCRYPTION_KEYWORD).encode()).hexdigest()
    return encrypted_password

# Password verification function
def verify_password(stored_password, provided_password):
    sha_signature = hashlib.sha256(provided_password.encode()).hexdigest()
    encrypted_provided = hashlib.sha256((sha_signature + ENCRYPTION_KEYWORD).encode()).hexdigest()
    return stored_password == encrypted_provided
