# README Proyek

## 📝 Deskripsi

Proyek ini adalah aplikasi web dengan arsitektur microservices yang diorkestrasi menggunakan Docker Compose. Proyek ini mencakup backend Python, a frontend React, dan berbagai layanan lain untuk proksi terbalik, keamanan, dan visualisasi data. Proyek ini dibuat untuk memenuhi tugas akhir di **IDN-Networkers**.

## 🚀 Tumpukan Teknologi

- **Frontend:**
    - ⚛️ React
    - ⚡ Vite
    - 💨 Tailwind CSS
    - 📜 JavaScript
- **Backend:**
    - 🐍 Python
    - 🌶️ Flask
    - 🎈 Streamlit
- **Web Server/Proxy:**
    - 🔒 Caddy
- **Tunneling:**
    - ☁️ Cloudflare Tunnel
- **Containerization & Orchestration:**
    - 🐳 Docker
    - 🎶 Docker Compose
- **Keamanan:**
    - 🛡️ Suricata

## 📂 Struktur Proyek

- **`backend/`**: Aplikasi backend inti Python.
- **`caddy/`**: Konfigurasi server web Caddy.
- **`cloudflared/`**: Konfigurasi Cloudflare Tunnel.
- **`frontend/`**: Aplikasi frontend berbasis React.
- **`scripts/`**: Kumpulan skrip utilitas untuk mengelola proyek.
- **`streamlit/`**: Aplikasi Streamlit.
- **`suricata/`**: Konfigurasi Suricata Intrusion Detection System (IDS).
- **`docker-compose.yml`**: File Docker Compose utama untuk mengorkestrasi semua layanan.

## 🏁 Memulai

Untuk menjalankan proyek ini, Anda harus menginstal Docker dan Docker Compose. Kemudian, Anda dapat menjalankan perintah berikut:

```bash
docker-compose up -d
```

Perintah ini akan memulai semua layanan di latar belakang.

## 🐳 Penggunaan Docker Compose

File `docker-compose.yml` adalah pusat dari proyek ini. Ini mendefinisikan semua layanan, jaringan, dan volume yang diperlukan untuk menjalankan aplikasi. Berikut adalah beberapa perintah yang berguna:

- **Memulai semua layanan:**
    ```bash
    docker-compose up -d
    ```
- **Menghentikan semua layanan:**
    ```bash
    docker-compose down
    ```
- **Melihat log dari semua layanan:**
    ```bash
    docker-compose logs -f
    ```
- **Melihat log dari layanan tertentu:**
    ```bash
    docker-compose logs -f <nama_layanan>
    ```
- **Membangun kembali gambar Docker:**
    ```bash
    docker-compose build
    ```

## 🐛 Debugging

Berikut adalah beberapa tips untuk men-debug berbagai layanan:

- **Frontend:**
    - Periksa log dari container `frontend` untuk setiap kesalahan.
    - Gunakan alat pengembang browser untuk memeriksa konsol dan permintaan jaringan.
- **Backend:**
    - Periksa log dari container `backend` untuk setiap kesalahan.
    - Gunakan `docker exec` untuk masuk ke dalam container dan menjalankan perintah.
- **Caddy:**
    - Periksa log dari container `caddy` untuk masalah proksi terbalik.
- **Cloudflared:**
    - Periksa log dari container `cloudflared` untuk masalah tunneling.
- **Streamlit:**
    - Periksa log dari container `streamlit` untuk kesalahan aplikasi.
- **Suricata:**
    - Periksa log dari container `suricata` untuk peringatan keamanan.

## 🔐 Keamanan

Untuk alasan keamanan, sangat disarankan untuk mengubah kredensial default. Kredensial default disediakan dalam file berikut:

- `caddy/.auth.hashes`
- `backend/creds.json`

## 🙈 File yang Diabaikan

Proyek ini berisi file `.gitignore` yang dikonfigurasi untuk mengabaikan file dan direktori yang tidak diperlukan untuk repositori. Ini termasuk:

- `node_modules/`
- `.env`
- `*.log`
- `*.bak*`
- `pnpm-lock.yaml`
- `pnpm-workspace.yaml`
- dan file umum lainnya.