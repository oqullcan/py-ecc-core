import argparse
import sys
import hashlib
import secrets

from ecc_core import Point
from ecdsa import sign_message, verify_signature, generate_key_pair
from serialization import (
    serialize_private_key, serialize_public_key, serialize_signature,
    deserialize_private_key, deserialize_public_key, deserialize_signature
)
from curves import AVAILABLE_CURVES, secp256k1


def generate(args):
    """'generate' komutunu çalıştırır: yeni anahtar çifti oluşturur."""
    curve = AVAILABLE_CURVES.get(args.curve, secp256k1)
    private_key, public_key = generate_key_pair(curve)

    priv_pem = serialize_private_key(private_key, public_key)
    pub_pem = serialize_public_key(public_key)

    priv_path = args.priv
    pub_path = args.pub

    with open(priv_path, 'wb') as f:
        f.write(priv_pem)
    with open(pub_path, 'wb') as f:
        f.write(pub_pem)

    print(f"✅ Anahtar çifti oluşturuldu.")
    print(f"  -> Özel anahtar: {priv_path}")
    print(f"  -> Ortak anahtar: {pub_path}")


def sign(args):
    """'sign' komutunu çalıştırır: bir dosyayı imzalar."""
    try:
        with open(args.priv, 'rb') as f:
            private_key, curve = deserialize_private_key(f.read())
    except FileNotFoundError:
        print(f"❌ Hata: Özel anahtar dosyası bulunamadı: {args.priv}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Hata: Özel anahtar dosyası okunamadı: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.file, 'rb') as f:
            message = f.read()
    except FileNotFoundError:
        print(f"❌ Hata: Mesaj dosyası bulunamadı: {args.file}", file=sys.stderr)
        sys.exit(1)

    signature = sign_message(private_key, message, curve)
    sig_der = serialize_signature(signature)

    with open(args.out, 'wb') as f:
        f.write(sig_der)

    print(f"✅ Mesaj '{args.file}' başarıyla imzalandı.")
    print(f"  -> İmza kaydedildi: {args.out}")


def verify(args):
    """'verify' komutunu çalıştırır: bir imzanın geçerliliğini kontrol eder."""
    try:
        with open(args.pub, 'rb') as f:
            public_key = deserialize_public_key(f.read())
    except Exception as e:
        print(f"❌ Hata: Ortak anahtar dosyası okunamadı: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.file, 'rb') as f:
            message = f.read()
    except FileNotFoundError:
        print(f"❌ Hata: Mesaj dosyası bulunamadı: {args.file}", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(args.sig, 'rb') as f:
            signature = deserialize_signature(f.read())
    except Exception as e:
        print(f"❌ Hata: İmza dosyası okunamadı: {e}", file=sys.stderr)
        sys.exit(1)

    if verify_signature(public_key, message, signature):
        print("✅ İmza Geçerli.")
    else:
        print("❌ İmza Geçersiz.")
        sys.exit(1)


def main():
    """CLI için ana argüman ayrıştırıcısını kurar ve çalıştırır."""
    parser = argparse.ArgumentParser(
        description="ECC (Eliptik Eğri Kriptografi) için basit bir komut satırı aracı."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Alt komutlar")

    # 'generate' komutu
    gen_parser = subparsers.add_parser("generate", help="Yeni bir özel/ortak anahtar çifti oluşturur.")
    gen_parser.add_argument("--curve", default="secp256k1", choices=AVAILABLE_CURVES.keys(),
                            help="Kullanılacak eğri (varsayılan: secp256k1)")
    gen_parser.add_argument("--priv", default="private_key.pem", help="Özel anahtar için çıktı dosyası.")
    gen_parser.add_argument("--pub", default="public_key.pem", help="Ortak anahtar için çıktı dosyası.")
    gen_parser.set_defaults(func=generate)

    # 'sign' komutu
    sign_parser = subparsers.add_parser("sign", help="Verilen bir dosyayı özel anahtarla imzalar.")
    sign_parser.add_argument('--priv', required=True, help='Kullanılacak özel anahtarın yolu (PEM).')
    sign_parser.add_argument('--file', required=True, help='İmzalanacak dosyanın yolu.')
    sign_parser.add_argument('--out', default='message.sig', help='İmzanın kaydedileceği çıktı dosyası (DER).')
    sign_parser.set_defaults(func=sign)

    # 'verify' komutu
    verify_parser = subparsers.add_parser('verify', help='Bir dosyanın imzasını doğrular.')
    verify_parser.add_argument('--pub', required=True, help='Kullanılacak ortak anahtarın yolu (PEM).')
    verify_parser.add_argument('--file', required=True, help='Doğrulanacak orijinal dosyanın yolu.')
    verify_parser.add_argument('--sig', required=True, help='Doğrulanacak imza dosyasının yolu (DER).')
    verify_parser.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
