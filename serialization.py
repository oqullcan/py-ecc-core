from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature
)

from ecc_core import Curve, Point
from ecdsa import Signature
from curves import AVAILABLE_CURVES

# Kendi Curve nesnelerimizi 'cryptography' kütüphanesinin nesnelerine haritala
CRYPTO_CURVES = {
    "secp256k1": ec.SECP256K1(),
    "secp256r1": ec.SECP256R1(),
}


# --- İmza Formatlama (DER) ---

def encode_signature_to_der(signature: Signature) -> bytes:
    """İmzayı (r, s) DER formatına kodlar."""
    return encode_dss_signature(signature.r, signature.s)

def decode_signature_from_der(der_bytes: bytes) -> Signature:
    """DER formatındaki imzayı (r, s) olarak okur."""
    r, s = decode_dss_signature(der_bytes)
    return Signature(r, s)


# --- Anahtar Formatlama (PEM) ---

def serialize_private_key(private_key: int, public_key: Point) -> bytes:
    """Özel anahtarı PEM formatında serileştirir."""
    curve_name = public_key.curve.name
    if curve_name not in CRYPTO_CURVES:
        raise ValueError(f"Serileştirme için desteklenmeyen eğri: {curve_name}")

    crypto_curve = CRYPTO_CURVES[curve_name]

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=public_key.x,
        y=public_key.y,
        curve=crypto_curve
    )

    private_key_obj = ec.EllipticCurvePrivateNumbers(
        private_value=private_key,
        public_numbers=public_numbers
    ).private_key()

    return private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key: Point) -> bytes:
    """Ortak anahtarı PEM formatında serileştirir."""
    curve_name = public_key.curve.name
    if curve_name not in CRYPTO_CURVES:
        raise ValueError(f"Serileştirme için desteklenmeyen eğri: {curve_name}")

    crypto_curve = CRYPTO_CURVES[curve_name]

    public_key_obj = ec.EllipticCurvePublicNumbers(
        x=public_key.x,
        y=public_key.y,
        curve=crypto_curve
    ).public_key()

    return public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_private_key(pem_bytes: bytes) -> tuple[int, Curve]:
    """PEM dosyasından özel anahtarı ve eğriyi okur."""
    private_key_obj = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(private_key_obj, ec.EllipticCurvePrivateKey):
        raise TypeError("PEM dosyası bir eliptik eğri özel anahtarı içermiyor.")

    curve_name = private_key_obj.curve.name
    if curve_name not in AVAILABLE_CURVES:
        raise ValueError(f"Desteklenmeyen eğri: {curve_name}")

    curve = AVAILABLE_CURVES[curve_name]
    private_numbers = private_key_obj.private_numbers()
    return private_numbers.private_value, curve


def deserialize_public_key(pem_bytes: bytes) -> Point:
    """PEM dosyasından ortak anahtarı okur."""
    public_key_obj = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(public_key_obj, ec.EllipticCurvePublicKey):
        raise TypeError("PEM dosyası bir eliptik eğri ortak anahtarı içermiyor.")
    
    curve_name = public_key_obj.curve.name
    if curve_name not in AVAILABLE_CURVES:
        raise ValueError(f"PEM dosyasından okunan eğri desteklenmiyor: {curve_name}")
    
    curve = AVAILABLE_CURVES[curve_name]
    public_numbers = public_key_obj.public_numbers()
    return Point(curve, public_numbers.x, public_numbers.y)

def serialize_signature(signature: Signature) -> bytes:
    """İmzayı (r,s) DER formatına serileştirir."""
    r, s = signature
    return encode_dss_signature(r, s)

def deserialize_signature(der_bytes: bytes) -> Signature:
    """DER formatından imzayı (r,s) olarak okur."""
    r, s = decode_dss_signature(der_bytes)
    return r, s 