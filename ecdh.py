import secrets
from typing import Tuple

from ecc_core import Curve, Point

def generate_key_pair(curve: Curve) -> Tuple[int, Point]:
    """
    Verilen bir eliptik eğri üzerinde bir özel/ortak anahtar çifti oluşturur.

    Args:
        curve: Anahtar çiftinin oluşturulacağı eliptik eğri. 
               Bu eğri nesnesi üreteç noktası (g) ve mertebesini (n) içermelidir.

    Returns:
        (private_key, public_key) şeklinde bir tuple.
        private_key: Güvenli bir şekilde üretilmiş rastgele bir tamsayı.
        public_key: Karşılık gelen ortak anahtar noktası (private_key * G).
    """
    if not curve.g or not curve.n:
        raise ValueError("Eğri, üreteç noktası (g) ve mertebe (n) içermelidir.")

    # 1 <= private_key < n aralığında güvenli rastgele bir tamsayı üret
    # secrets.randbelow(n-1) -> [0, n-2] aralığında üretir. +1 ekleyerek [1, n-1] yaparız.
    private_key = secrets.randbelow(curve.n - 1) + 1
    
    public_key = private_key * curve.g
    
    return private_key, public_key

def derive_shared_secret(private_key: int, public_key_other: Point) -> Point:
    """
    Kendi özel anahtarımız ve diğer tarafın ortak anahtarı ile paylaşılan sırrı hesaplar.

    Args:
        private_key: Kendi özel anahtarımız.
        public_key_other: Diğer tarafın ortak anahtarı.

    Returns:
        Paylaşılan sır olan eliptik eğri noktası (private_key * public_key_other).
        Genellikle bu noktanın x koordinatı simetrik şifreleme anahtarı olarak kullanılır.
    """
    shared_secret_point = private_key * public_key_other
    return shared_secret_point

# --- Örnek Kullanım ---
if __name__ == "__main__":
    # Bitcoin tarafından kullanılan standart secp256k1 eğrisini tanımla
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    # Eğri ve üreteç noktasını oluştur
    secp256k1 = Curve(a, b, p, n=n)
    g = Point(secp256k1, gx, gy)
    secp256k1.g = g

    print("ECDH Anahtar Değişim Simülasyonu (secp256k1 eğrisi ile)")
    print("-" * 60)

    # 1. Alice anahtar çiftini oluşturur
    private_key_alice, public_key_alice = generate_key_pair(secp256k1)
    print(f"Alice'in Özel Anahtarı: {private_key_alice:x}")
    print(f"Alice'in Ortak Anahtarı (x, y): ({public_key_alice.x:x}, {public_key_alice.y:x})\n")

    # 2. Bob anahtar çiftini oluşturur
    private_key_bob, public_key_bob = generate_key_pair(secp256k1)
    print(f"Bob'un Özel Anahtarı: {private_key_bob:x}")
    print(f"Bob'un Ortak Anahtarı (x, y): ({public_key_bob.x:x}, {public_key_bob.y:x})\n")
    
    print("-" * 60)
    print("Anahtarlar değiş tokuş ediliyor...")
    print("-" * 60)

    # 3. Taraflar paylaşılan sırrı hesaplar
    # Alice, kendi özel anahtarını ve Bob'un ortak anahtarını kullanır
    shared_secret_alice = derive_shared_secret(private_key_alice, public_key_bob)
    print(f"Alice'in Hesapladığı Paylaşılan Sır (x): {shared_secret_alice.x:x}\n")

    # Bob, kendi özel anahtarını ve Alice'in ortak anahtarını kullanır
    shared_secret_bob = derive_shared_secret(private_key_bob, public_key_alice)
    print(f"Bob'un Hesapladığı Paylaşılan Sır (x):   {shared_secret_bob.x:x}\n")
    
    # 4. Paylaşılan sırların aynı olduğunu doğrula
    try:
        assert shared_secret_alice.x == shared_secret_bob.x
        assert shared_secret_alice.y == shared_secret_bob.y
        print("✅ Başarılı! Her iki taraf da aynı paylaşılan sırrı elde etti.")
        print("Artık bu sır (genellikle x koordinatı), simetrik bir şifreleme için anahtar olarak kullanılabilir.")
    except AssertionError:
        print("❌ Hata! Paylaşılan sırlar eşleşmiyor.")
