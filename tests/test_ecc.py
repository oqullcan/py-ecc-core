import sys
import os
import unittest
import hashlib
import secrets
import subprocess

# Proje kök dizinini Python yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ecc_core import Point
from ecdh import generate_key_pair as ecdh_generate_key_pair, derive_shared_secret
from ecdsa import sign_message, verify_signature, generate_key_pair as ecdsa_generate_key_pair
from curves import secp256k1, secp256r1


class TestECC(unittest.TestCase):
    def test_point_arithmetic_consistency(self):
        """
        Nokta aritmetiğinin iç tutarlılığını kontrol eder.
        Sabit kodlanmış değerler yerine (2*G == G+G) gibi temel özellikleri test eder.
        """
        p1 = secp256k1.g
        
        # Test 1: İkiye katlama ve toplamanın tutarlılığı
        p2_mul = 2 * p1
        p2_add = p1 + p1
        self.assertEqual(p2_mul, p2_add, "2*G ve G+G aynı sonucu vermeli.")

        # Test 2: Skaler çarpma tutarlılığı
        p3_mul = 3 * p1
        p3_add = p2_mul + p1
        self.assertEqual(p3_mul, p3_add, "3*G ve (2*G)+G aynı sonucu vermeli.")

    def test_cli_full_flow_secp256r1(self):
        """
        Komut satırı arayüzünün (CLI) secp256r1 eğrisiyle tam akışını test eder.
        generate -> sign -> verify
        """
        priv_key_path = "test_priv_r1.pem"
        pub_key_path = "test_pub_r1.pem"
        message_path = "test_message_r1.txt"
        signature_path = "test_sig_r1.sig"
        files_to_clean = [priv_key_path, pub_key_path, message_path, signature_path]

        try:
            # 1. Anahtar oluştur
            gen_cmd = [
                "python3", "main.py", "generate", "--curve", "secp256r1",
                "--priv", priv_key_path, "--pub", pub_key_path
            ]
            subprocess.run(gen_cmd, check=True, capture_output=True)
            self.assertTrue(os.path.exists(priv_key_path))

            # 2. Mesaj oluştur ve imzala
            with open(message_path, "w") as f:
                f.write("secp256r1 üzerinde bir test mesajı.")
            
            sign_cmd = [
                "python3", "main.py", "sign",
                "--priv", priv_key_path, "--file", message_path, "--out", signature_path
            ]
            subprocess.run(sign_cmd, check=True, capture_output=True)
            self.assertTrue(os.path.exists(signature_path))

            # 3. İmzayı doğrula
            verify_cmd = [
                "python3", "main.py", "verify",
                "--pub", pub_key_path, "--file", message_path, "--sig", signature_path
            ]
            result = subprocess.run(verify_cmd, check=True, capture_output=True, text=True)
            self.assertIn("İmza Geçerli", result.stdout)

        finally:
            # Test sonrası oluşturulan dosyaları temizle
            for f in files_to_clean:
                if os.path.exists(f):
                    os.remove(f)

    def test_ecdh_key_exchange(self):
        """ECDH anahtar değişimini test eder. Alice ve Bob aynı sırrı üretmeli."""
        alice_priv, alice_pub = ecdh_generate_key_pair(secp256k1)
        bob_priv, bob_pub = ecdh_generate_key_pair(secp256k1)

        # Alice, Bob'un ortak anahtarını kullanarak sırrı hesaplar
        secret1 = derive_shared_secret(alice_priv, bob_pub)
        
        # Bob, Alice'in ortak anahtarını kullanarak sırrı hesaplar
        secret2 = derive_shared_secret(bob_priv, alice_pub)

        self.assertEqual(secret1, secret2, "Alice ve Bob'un paylaşılan sırları eşleşmeli.")

    def test_ecdsa_signature_correctness(self):
        """ECDSA imzalama ve doğrulama mantığını test eder."""
        private_key, public_key = ecdsa_generate_key_pair(secp256k1)
        message = b"ECDSA icin test mesaji."

        # Geçerli imza doğrulanmalı
        signature = sign_message(private_key, message, secp256k1)
        self.assertTrue(verify_signature(public_key, message, signature), "Geçerli bir imza doğrulanmalıdır.")

        # Yanlış mesajla doğrulama başarısız olmalı
        wrong_message = b"Bu yanlis mesaj."
        self.assertFalse(verify_signature(public_key, wrong_message, signature), "Yanlış mesajla doğrulama başarısız olmalı.")

        # Yanlış anahtarla doğrulama başarısız olmalı
        wrong_private_key, wrong_public_key = ecdsa_generate_key_pair(secp256k1)
        self.assertFalse(verify_signature(wrong_public_key, message, signature), "Yanlış anahtarla doğrulama başarısız olmalı.")


if __name__ == '__main__':
    unittest.main()
