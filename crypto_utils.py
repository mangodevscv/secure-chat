from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import os
import binascii

# =====================
# Geração de Chaves ECC
# =====================
def generate_keys():
    """
    Gera par de chaves usando Elliptic Curve Cryptography (ECC)
    Curva: SECP256R1 (também conhecida como P-256)
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

# =====================
# Serialização de Chaves
# =====================
def serialize_public(pub):
    """Serializa chave pública para formato PEM"""
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def serialize_private(priv):
    """Serializa chave privada para formato PEM"""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

def load_public(pem):
    """Carrega chave pública de formato PEM"""
    return serialization.load_pem_public_key(pem.encode())

def load_private(pem):
    """Carrega chave privada de formato PEM"""
    return serialization.load_pem_private_key(pem.encode(), password=None)

# =====================
# Derivação de Chave de Sessão (ECDH)
# =====================
def derive_session(priv, peer_pub):
    """
    Deriva chave de sessão simétrica usando ECDH + HKDF
    
    ECDH (Elliptic Curve Diffie-Hellman):
    - Permite que duas partes concordem numa chave secreta partilhada
    - Usa suas chaves privadas e públicas
    
    HKDF (HMAC-based Key Derivation Function):
    - Deriva uma chave criptograficamente forte do segredo partilhado
    - Usa SHA-256 como função hash
    """
    # Troca ECDH
    shared = priv.exchange(ec.ECDH(), peer_pub)
    
    # Deriva chave usando HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits para AES-256
        salt=None,
        info=b"secure-chat"
    )
    return hkdf.derive(shared)

# =====================
# Cifra Simétrica (AES-GCM)
# =====================
def encrypt(key, msg):
    """
    Cifra mensagem usando AES-GCM (Galois/Counter Mode)
    
    AES-GCM:
    - Fornece confidencialidade (cifra) e autenticidade (MAC)
    - Cifra autenticada (AEAD - Authenticated Encryption with Associated Data)
    - Não precisa de HMAC separado
    
    Retorna: (nonce_hex, ciphertext_hex)
    """
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 96 bits (recomendado para GCM)
    cipher = aes.encrypt(nonce, msg.encode(), None)
    
    return binascii.hexlify(nonce).decode(), binascii.hexlify(cipher).decode()

def decrypt(key, nonce_hex, cipher_hex):
    """
    Decifra mensagem usando AES-GCM
    
    Verifica automaticamente a autenticidade através do MAC incluído
    Levanta exceção se a mensagem foi alterada
    """
    aes = AESGCM(key)
    return aes.decrypt(
        binascii.unhexlify(nonce_hex),
        binascii.unhexlify(cipher_hex),
        None
    ).decode()

# =====================
# Assinatura Digital (ECDSA)
# =====================
def sign_message(priv_key, message):
   
    if isinstance(message, str):
        message = message.encode()
    elif not isinstance(message, bytes):
        message = str(message).encode()
    
    signature = priv_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    return binascii.hexlify(signature).decode()

def verify_signature(pub_key, message, signature_hex):
    """
    Verifica assinatura digital
    
    Retorna: True se válida, False caso contrário
    """
    try:
        if isinstance(message, str):
            message = message.encode()
        elif not isinstance(message, bytes):
            message = str(message).encode()
        
        signature = binascii.unhexlify(signature_hex)
        
        pub_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Verificação de assinatura falhou: {e}")
        return False

# =====================
# Hash Criptográfico
# =====================
def hash_message(message):
    """
    Calcula hash SHA-256 de uma mensagem
    
    Retorna: hash em formato hexadecimal
    """
    if isinstance(message, str):
        message = message.encode()
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return binascii.hexlify(digest.finalize()).decode()

# =====================
# Utilitários
# =====================
def generate_nonce(length=12):
    """Gera nonce aleatório"""
    return os.urandom(length)

def bytes_to_hex(data):
    """Converte bytes para hexadecimal"""
    return binascii.hexlify(data).decode()

def hex_to_bytes(hex_str):
    """Converte hexadecimal para bytes"""
    return binascii.unhexlify(hex_str)

# =====================
# Informações do Sistema
# =====================
def get_crypto_info():
    """Retorna informações sobre as primitivas criptográficas usadas"""
    return {
        "asymmetric": "ECC (SECP256R1 / P-256)",
        "key_exchange": "ECDH (Elliptic Curve Diffie-Hellman)",
        "kdf": "HKDF-SHA256",
        "symmetric": "AES-256-GCM",
        "signature": "ECDSA-SHA256",
        "hash": "SHA-256"
    }

def verify_pin(pin, hashed_pin):
    """Verifica se o PIN corresponde ao hash"""
    import hashlib
    return hashlib.sha256(pin.encode()).hexdigest() == hashed_pin