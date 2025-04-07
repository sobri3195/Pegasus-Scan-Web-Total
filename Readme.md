# Pegasus Scan Web Total

Pegasus Scan Web Total adalah scanner keamanan web komprehensif yang dapat mendeteksi berbagai kerentanan pada aplikasi web. Dikembangkan dengan fokus pada keamanan dan kemudahan penggunaan.

## Author Information

- **Author**: Letda Kes Dr. Sobri, S.Kom.
- **Contact**: muhammadsobrimaulana31@gmail.com
- **GitHub**: [github.com/sobri3195](https://github.com/sobri3195)
- **Donate**: [https://lynk.id/muhsobrimaulana](https://lynk.id/muhsobrimaulana)

## Features

- **Pemindaian Kerentanan Umum**: Mendeteksi jalur-jalur yang berpotensi berbahaya
- **Deteksi XSS**: Mengidentifikasi kerentanan Cross-Site Scripting
- **Deteksi SQL Injection**: Menemukan titik-titik yang rentan terhadap SQL Injection
- **Brute Force Direktori**: Menemukan direktori tersembunyi pada target
- **Enumerasi Subdomain**: Mengidentifikasi subdomain yang terkait dengan domain target
- **Analisis Header HTTP**: Memeriksa konfigurasi header keamanan
- **Pemindaian Konfigurasi SSL/TLS**: Mengevaluasi keamanan konfigurasi SSL/TLS
- **Analisis Robots.txt**: Mengekstrak informasi berharga dari file robots.txt
- **Deteksi File Sensitif**: Mengidentifikasi file-file sensitif yang terekspos
- **Deteksi CMS**: Menentukan sistem manajemen konten yang digunakan oleh target

## Sistem Proteksi

Pegasus Scan Web Total dilengkapi dengan sistem proteksi canggih:

- **Verifikasi Lisensi**: Memastikan hanya pengguna resmi yang dapat menggunakan alat ini
- **Pengecekan Integritas Kode**: Mencegah modifikasi tidak sah pada kode sumber
- **Anti-Debugging**: Mencegah reverse engineering dan analisis kode
- **Kompilasi Protektif**: Mengamankan kode dari upaya pembajakan

## Requirements

- Python 3.6+
- Paket yang diperlukan: requests, concurrent.futures, dll.

## Installation

```bash
# Clone repository
git clone https://github.com/sobri3195/pegasus-scanner.git
cd pegasus-scanner

# Install dependencies
pip install -r requirements.txt
```

## Aktivasi Lisensi

Saat pertama kali dijalankan, Pegasus Scan Web Total memerlukan aktivasi:

1. Jalankan program dengan parameter yang diinginkan
2. Saat prompt aktivasi muncul, masukkan kunci aktivasi: `sobri`
3. Program akan melanjutkan eksekusi secara normal setelah aktivasi berhasil

Aktivasi hanya perlu dilakukan sekali. Kunci aktivasi didapatkan langsung dari author.

## Usage

```bash
python main.py -u https://example.com -w wordlist.txt -o results.json -v
```

### Command-line Arguments

- `-u, --url`: URL target yang akan dipindai (wajib)
- `-w, --wordlist`: Path ke file wordlist (default: wordlist.txt)
- `-t, --threads`: Jumlah thread untuk operasi konkuren (default: 10)
- `-o, --output`: Path file output untuk menyimpan hasil
- `-f, --format`: Format output (json atau csv, default: json)
- `--timeout`: Timeout permintaan dalam detik (default: 10)
- `-v, --verbose`: Mengaktifkan output yang lebih detail

## Contoh Penggunaan

### Pemindaian Dasar

```bash
python main.py -u https://example.com
```

### Pemindaian Mendetail dengan Wordlist Kustom

```bash
python main.py -u https://example.com -w custom_wordlist.txt -v
```

### Menyimpan Hasil Pemindaian sebagai CSV

```bash
python main.py -u https://example.com -o results.csv -f csv
```

### Meningkatkan Performa dengan Thread Lebih Banyak

```bash
python main.py -u https://example.com -t 20
```

## Contoh Output

```
[2023-04-07 20:52:13] [INFO] Starting Pegasus Scan on https://example.com
[2023-04-07 20:52:14] [FOUND] Vulnerable Path: https://example.com/admin
[2023-04-07 20:52:15] [FOUND] XSS Vulnerability: Payload: <script>alert('XSS')</script>
[2023-04-07 20:52:16] [FOUND] Directory Found: https://example.com/backup
[2023-04-07 20:52:20] [INFO] Scan completed in 7.23 seconds
[2023-04-07 20:52:20] [INFO] Found 3 issues
```

## Troubleshooting

Jika mengalami masalah:

1. **Error Aktivasi**: Pastikan menggunakan kunci aktivasi yang benar (`sobri`)
2. **File Wordlist Tidak Ditemukan**: Pastikan path ke wordlist valid
3. **SSL/TLS Error**: Periksa apakah target menggunakan protokol HTTPS yang valid
4. **Koneksi Timeout**: Coba tingkatkan nilai `--timeout` jika target lambat merespons

## Disclaimer

Alat ini hanya untuk tujuan pendidikan dan pengujian keamanan yang sah. Jangan gunakan terhadap sistem yang tidak Anda miliki izin untuk diuji. Penyalahgunaan alat ini dapat melanggar hukum dan etika.

---

© 2023 Letda Kes Dr. Sobri, S.Kom. All rights reserved.