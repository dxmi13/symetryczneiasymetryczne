from fastapi import FastAPI, HTTPException, status, Body
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Dict
import os

app = FastAPI()

# Szyfrowanie symetryczne
symmetric_key: str = None

class SymmetricKey(BaseModel):
    key: str  # Klucz w formacie hex

class Message(BaseModel):
    message: str

@app.get("/symmetric/key")
async def get_symmetric_key() -> Dict[str, str]:
    """Generuje i zwraca losowy symetryczny klucz w formacie hex."""
    global symmetric_key
    symmetric_key = os.urandom(32).hex()
    return {"key": symmetric_key}

@app.post("/symmetric/key")
async def set_symmetric_key(key: SymmetricKey) -> Dict[str, str]:
    """Ustawia symetryczny klucz na podstawie danych użytkownika."""
    global symmetric_key
    symmetric_key = key.key
    return {"message": "Klucz zaktualizowano pomyślnie"}

@app.post("/symmetric/encode")
async def encode_message(message: Message) -> Dict[str, str]:
    """Szyfruje wiadomość używając aktualnie ustawionego klucza."""
    if symmetric_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Symetryczny klucz nie został ustawiony.")
    key_bytes = bytes.fromhex(symmetric_key)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.message.encode()) + encryptor.finalize()
    return {"encrypted_message": encrypted_message.hex(), "nonce": nonce.hex()}

@app.post("/symmetric/decode")
async def decode_message(encrypted: Message) -> Dict[str, str]:
    """Odszyfrowuje wiadomość używając aktualnie ustawionego klucza."""
    if symmetric_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Klucz nie został ustawiony.")
    key_bytes = bytes.fromhex(symmetric_key)
    nonce = bytes.fromhex(encrypted.message[:32])
    encrypted_message = bytes.fromhex(encrypted.message[32:])
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return {"decrypted_message": decrypted_message.decode()}

# Szyfrowanie asymetryczne
private_key = None
public_key = None

@app.get("/asymmetric/key")
async def get_asymmetric_key() -> Dict[str, str]:
    """Generuje i zwraca nowe klucze."""
    global private_key, public_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "private_key": private_pem.decode(),
        "public_key": public_pem.decode()
    }

@app.post("/asymmetric/key")
async def set_asymmetric_keys(keys: Dict[str, str]) -> Dict[str, str]:
    """Ustawia klucze asymetryczne na podstawie danych użytkownika."""
    global private_key, public_key
    private_key = serialization.load_pem_private_key(
        keys['private_key'].encode(),
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return {"message": "Klucze asymetryczne zaktualizowane pomyślnie"}

@app.post("/asymmetric/sign")
async def sign_message(message: Message) -> Dict[str, str]:
    """Podpisuje wiadomość używając aktualnego klucza prywatnego."""
    if private_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Klucz prywatny nie został ustawiony.")
    signature = private_key.sign(
        message.message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {"signature": signature.hex()}

@app.post("/asymmetric/verify")
async def verify_message(signature: Dict[str, str], message: Message = Body(...)) -> Dict[str, str]:
    """Weryfikuje podpisaną wiadomość używając aktualnego klucza publicznego."""
    if public_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Klucz publiczny nie został ustawiony.")
    try:
        public_key.verify(
            bytes.fromhex(signature['signature']),
            message.message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"message": "Weryfikacja pomyślna"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Weryfikacja nieudana")

@app.post("/asymmetric/encode")
async def encode_asymmetric(message: Message) -> Dict[str, str]:
    """Szyfruje wiadomość używając aktualnego klucza publicznego."""
    if public_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Klucz publiczny nie został ustawiony.")
    encrypted_message = public_key.encrypt(
        message.message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"encrypted_message": encrypted_message.hex()}

@app.post("/asymmetric/decode")
async def decode_asymmetric(encrypted: Message) -> Dict[str, str]:
    """Odszyfrowuje wiadomość używając aktualnego klucza prywatnego."""
    if private_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Klucz prywatny nie został ustawiony.")
    decrypted_message = private_key.decrypt(
        bytes.fromhex(encrypted.message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_message": decrypted_message.decode()}

