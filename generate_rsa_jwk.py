import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwcrypto import jwk

this_exponent = 65537
encoded_exponent = base64.b64encode(str(this_exponent))

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()

plaintext = b'this is the correct plaintext!'
encrypted = base64.b64encode(public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
))
payload = {"lol":"mao"}
headers = {"type":"jwt"}
this_jwt = jwt.encode(payload,private_key,algorithm="RS256",headers=headers)
decoded = jwt.api_jwt.decode_complete(this_jwt, public_key, algorithms=["RS256"])

print(f"this_jwt:{this_jwt}")
print(f"decoded:{decoded}")

this_jwk = jwk.JWK.generate(kty='RSA', size=2048)
print(f"this_jwk:{this_jwk}")
