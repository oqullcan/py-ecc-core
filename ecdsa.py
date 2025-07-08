import hashlib
import hmac
import secrets
from typing import Tuple

# Üst dizindeki modülleri import etmek için
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from ecc_core import Curve, Point

Signature = Tuple[int, int]


def generate_key_pair(curve: Curve) -> Tuple[int, Point]:
    """Verilen eğri üzerinde yeni bir özel/ortak anahtar çifti oluşturur."""
    private_key = secrets.randbelow(curve.n)
    public_key = private_key * curve.g
    return private_key, public_key


def _rfc6979_k(priv_key: int, msg_hash: bytes, curve: Curve) -> int:
    """
    RFC 6979'a göre deterministik 'k' değeri üretir.
    Bu, zayıf RNG'lerden (rastgele sayı üreteci) kaynaklanan hataları önler.
    """
    n = curve.n
    hash_len = len(msg_hash)
    n_len = (n.bit_length() + 7) // 8

    # RFC 6979, Adım B, C
    v = b'\x01' * hash_len
    k = b'\x00' * hash_len

    # RFC 6979, Adım D
    k = hmac.new(k, v + b'\x00' + priv_key.to_bytes(n_len, 'big') + msg_hash, hashlib.sha256).digest()

    # RFC 6979, Adım E
    v = hmac.new(k, v, hashlib.sha256).digest()

    # RFC 6979, Adım F
    k = hmac.new(k, v + b'\x01' + priv_key.to_bytes(n_len, 'big') + msg_hash, hashlib.sha256).digest()

    # RFC 6979, Adım G
    v = hmac.new(k, v, hashlib.sha256).digest()

    # RFC 6979, Adım H
    while True:
        # H1
        t = b''

        # H2: t'nin bit uzunluğu, grup mertebesinin bit uzunluğuna ulaşana kadar v'yi hash'le
        while len(t) < n_len:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v

        # H3: Aday k'yı türet
        k_int = int.from_bytes(t, 'big')
        k_int >>= len(t) * 8 - n.bit_length()

        if 1 <= k_int < n:
            return k_int

        # Geçersiz k, tekrar dene
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_message(private_key: int, message: bytes, curve: Curve) -> Signature:
    """Bir mesajı özel anahtarla imzalar (RFC 6979 kullanarak)."""
    msg_hash = hashlib.sha256(message).digest()

    k = _rfc6979_k(private_key, msg_hash, curve)
    r_point = k * curve.g
    r = r_point.x % curve.n
    if r == 0:
        # Çok nadir bir durum, standartlar yeniden denemeyi gerektirir.
        return sign_message(private_key, message, curve)

    s = (pow(k, -1, curve.n) * (int.from_bytes(msg_hash, 'big') + r * private_key)) % curve.n
    if s == 0:
        # Bu da çok nadir bir durum.
        return sign_message(private_key, message, curve)

    return (r, s)


def verify_signature(public_key: Point, message: bytes, signature: Signature) -> bool:
    """Bir imzanın, verilen mesaj ve ortak anahtar için geçerli olup olmadığını doğrular."""
    curve = public_key.curve
    msg_hash_int = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    r, s = signature

    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False

    s_inv = pow(s, -1, curve.n)
    u1 = (msg_hash_int * s_inv) % curve.n
    u2 = (r * s_inv) % curve.n

    p = u1 * curve.g + u2 * public_key

    if p.is_identity:
        return False

    return p.x % curve.n == r


# --- Örnek Kullanım ---
if __name__ == "__main__":
    # secp256k1 eğrisini tanımla
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    secp256k1 = Curve(a, b, p, n=n)
    g = Point(secp256k1, gx, gy)
    secp256k1.g = g

    print("ECDSA İmzalama ve Doğrulama Simülasyonu")
    print("-" * 60)

    # 1. Anahtar çifti oluştur
    private_key, public_key = generate_key_pair(secp256k1)
    print(f"Özel Anahtar (gizli): {private_key:x}")
    print(f"Ortak Anahtar (x, y): ({public_key.x:x}, \n\t\t   {public_key.y:x})\n")

    # 2. İmzalanacak mesajı ve hash'ini oluştur
    message = b"Bu guvenli bir test mesajidir."
    print(f'İmzalanacak Mesaj: "{message.decode()}"\n')

    # 3. Mesajı imzala
    signature = sign_message(private_key, message, secp256k1)
    print(f"Oluşturulan İmza (r, s): ({signature[0]:x}, \n\t\t\t{signature[1]:x})\n")

    # 4. İmzayı doğrula (doğru anahtar ve mesaj ile)
    is_valid = verify_signature(public_key, message, signature)
    print(f"Doğrulama Sonucu (orijinal): {is_valid}")
    assert is_valid
    print("✅ Başarılı! İmza doğru anahtar ve mesaj ile doğrulandı.\n")
    
    # --- Başarısız Senaryolar ---
    
    # 5. Farklı bir mesajla doğrulamayı dene
    wrong_message = b"Bu mesaj farkli!"
    wrong_hash_bytes = hashlib.sha256(wrong_message).digest()
    wrong_hash_int = int.from_bytes(wrong_hash_bytes, 'big')
    is_valid_wrong_msg = verify_signature(public_key, wrong_message, signature)
    print(f"Doğrulama Sonucu (yanlış mesaj): {is_valid_wrong_msg}")
    assert not is_valid_wrong_msg
    print("✅ Beklendiği gibi! Değiştirilmiş mesaj ile imza doğrulanamadı.\n")

    # 6. Farklı bir anahtarla doğrulamayı dene
    wrong_private_key, wrong_public_key = generate_key_pair(secp256k1)
    is_valid_wrong_key = verify_signature(wrong_public_key, message, signature)
    print(f"Doğrulama Sonucu (yanlış ortak anahtar): {is_valid_wrong_key}")
    assert not is_valid_wrong_key
    print("✅ Beklendiği gibi! Farklı bir ortak anahtar ile imza doğrulanamadı.")
