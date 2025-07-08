# Eliptik Eğri Kriptografisi (ECC) Implementasyonu
---

Bu proje, modern kriptografinin temel taşlarından biri olan **Eliptik Eğri Kriptografisi (ECC)**'nin temel algoritmalarını ve matematiksel altyapısını Python ile sıfırdan implemente etmeyi amaçlamaktadır. Proje, sadece teorik bir gösterim olmanın ötesine geçerek, **yan kanal saldırılarına karşı koruma**, **deterministik imzalama (RFC 6979)**, **standartlarla uyumlu dosya formatları (PEM/DER)** ve **çoklu eğri desteği** gibi profesyonel özellikleri de barındıran bir komut satırı aracına dönüşmüştür.

## Neden Bu Proje?

Eliptik Eğri Kriptografisi (ECC), RSA gibi daha eski asimetrik şifreleme algoritmalarına göre daha küçük anahtar boyutlarıyla aynı düzeyde güvenlik sunar. Bu verimlilik, onu mobil cihazlar, gömülü sistemler ve modern web güvenliği (TLS) gibi kaynakların kısıtlı olduğu alanlar için ideal kılar. Bu proje, ECC'nin arkasındaki matematiği ve pratik uygulamaları derinlemesine anlamak için bir öğrenme aracı olarak geliştirilmiştir.

## Teknik Derinlik ve Güvenlik

Bu implementasyon, sadece temel algoritmaları içermekle kalmaz, aynı zamanda gerçek dünya uygulamalarında karşılaşılan güvenlik zorluklarına yönelik çözümler de sunar:

1.  **Sabit Zamanlı Skaler Çarpma (Montgomery Ladder):** Nokta çarpma işlemi, zamanlama saldırıları gibi yan kanal saldırılarına karşı koruma sağlamak amacıyla sabit zamanlı çalışan **Montgomery Ladder** algoritması ile gerçekleştirilmiştir. Bu, işlemin süresinin, kullanılan özel anahtarın değerinden bağımsız olmasını sağlar.
2.  **Deterministik Efemeral Anahtar (RFC 6979):** ECDSA imza standardındaki en kritik zafiyetlerden biri, rastgele ve tahmin edilemez olması gereken `k` (efemeral anahtar) değeridir. Bu projede, `k` değeri, özel anahtar ve mesajın hash'inden deterministik olarak türeten **RFC 6979** standardı implemente edilmiştir. Bu, hatalı veya zayıf rastgele sayı üreteçlerinden kaynaklanabilecek güvenlik felaketlerini (örn. Sony PlayStation 3 vakası) tamamen ortadan kaldırır.

## Özellikler

*   **Sıfırdan Implementasyon:** Proje, temel matematiksel işlemlerden başlayarak eliptik eğri aritmetiğini sıfırdan uygular.
*   **Modüler Tasarım:** Kod; `ecc_core` (temel aritmetik), `ecdsa` (imzalama), `serialization` (dosya formatları) ve `curves` (eğri parametreleri) gibi modüllere ayrılarak anlaşılır ve genişletilebilir bir yapı sunar.
*   **Çoklu Eğri Desteği:** `secp256k1` (Bitcoin'in kullandığı) ve `secp256r1` (NIST P-256) gibi standart eğriler arasında seçim yapma imkanı.
*   **Endüstri Standardı Dosya Formatları:** `cryptography` kütüphanesi kullanılarak anahtarlar PEM, imzalar ise DER formatında standartlara uygun olarak kaydedilir ve okunur.
*   **Güvenli ve Profesyonel CLI:** `argparse` ile geliştirilmiş, `generate`, `sign` ve `verify` gibi alt komutlara sahip, kullanımı kolay bir komut satırı arayüzü.

## Bağımlılıklar

Proje, güvenli kriptografik işlemler ve standart dosya formatları için yalnızca `cryptography` kütüphanesine bağımlıdır.

*   `cryptography`: Yüksek seviyeli kriptografik tarifler ve düşük seviyeli kriptografik ilkelere erişim sağlar.

## Kurulum

Projeyi yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin:

```sh
# 1. Proje deposunu klonlayın
git clone https://github.com/oqullcan/py-ecc-core.git
cd py-ecc-core

# 2. Bir sanal ortam (virtual environment) oluşturun ve etkinleştirin
python3 -m venv venv
source venv/bin/activate  # Linux/macOS için
# venv\Scripts\activate  # Windows için

# 3. Gerekli kütüphaneyi yükleyin
pip install cryptography
```

## Komut Satırı Arayüzü (CLI)

Proje, üç ana komut içeren bir CLI aracı sunar:

### `generate`: Anahtar Çifti Oluşturma

Yeni bir özel ve ortak anahtar çifti oluşturur ve PEM formatında dosyalara kaydeder.

**Kullanım:**
```sh
python3 main.py generate [--curve <eğri>] [--priv <dosya>] [--pub <dosya>]
```

*   `--curve <eğri>`: Kullanılacak eliptik eğriyi belirtir. Desteklenenler: `secp256k1` (varsayılan), `secp256r1`.
*   `--priv <dosya>`: Özel anahtarın kaydedileceği dosya yolu (varsayılan: `private_key.pem`).
*   `--pub <dosya>`: Ortak anahtarın kaydedileceği dosya yolu (varsayılan: `public_key.pem`).

### `sign`: Mesaj İmzalama

Belirtilen bir dosyayı, özel bir anahtar kullanarak imzalar ve imzayı DER formatında kaydeder.

**Kullanım:**
```sh
python3 main.py sign --priv <özel_anahtar_dosyası> --file <mesaj_dosyası> [--out <imza_dosyası>]
```

### `verify`: İmza Doğrulama

Bir mesajın imzasını, ilgili ortak anahtarı kullanarak doğrular.

**Kullanım:**
```sh
python3 main.py verify --pub <ortak_anahtar_dosyası> --file <mesaj_dosyası> --sig <imza_dosyası>
```

## Örnek Kullanım Akışı

Aşağıdaki adımlar, `secp256k1` eğrisi üzerinde baştan sona bir kullanım senaryosunu gösterir.

```sh
# 1. Varsayılan eğri (secp256k1) ile bir anahtar çifti oluşturun
python3 main.py generate

# 2. İmzalanacak bir mesaj dosyası oluşturun
echo "Bu gizli bir test mesajıdır." > message.txt

# 3. Mesajı özel anahtarınızla imzalayın
python3 main.py sign --priv private_key.pem --file message.txt --out message.sig

# 4. İmzayı ortak anahtarınızla doğrulayın
# Bu komut "İmza Geçerli" çıktısını vermelidir.
python3 main.py verify --pub public_key.pem --file message.txt --sig message.sig

# 5. Mesajı değiştirerek doğrulamanın başarısız olduğunu test edin
echo "Bu mesaj değiştirildi." > message.txt

# Bu komut "İmza Geçersiz" çıktısını vermelidir.
python3 main.py verify --pub public_key.pem --file message.txt --sig message.sig
```

Farklı bir eğri kullanmak için (`secp256r1` gibi):
```sh
# Sadece generate komutunda eğriyi belirtmeniz yeterlidir.
# Diğer komutlar (sign, verify) anahtar dosyalarından doğru eğriyi otomatik olarak anlar.
python3 main.py generate --curve secp256r1 --priv r1_priv.pem --pub r1_pub.pem
```

## Gelecek Planları

*   **Parola Korumalı Anahtarlar:** Özel anahtarları şifreleyerek ek bir güvenlik katmanı ekleme.
*   **Şifreleme (ECIES):** Eliptik Eğri Entegre Şifreleme Şeması (ECIES) desteği ekleyerek dosyaların ve mesajların şifrelenmesini sağlama.
*   **Donanım Güvenlik Modülü (HSM) Desteği:** Özel anahtarların güvenli donanımlarda saklanması ve kullanılması için PKCS#11 arayüzü entegrasyonu.
*   **Diğer Standart Eğriler:** `secp384r1`, `brainpool` serisi gibi diğer popüler eğriler için destek ekleme.

---
