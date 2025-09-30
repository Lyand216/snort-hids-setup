# Snort HIDS Setup (PKL)

Skrip ini otomatis memasang Snort (HIDS), Mosquitto MQTT, dan deploy snort2mqtt bridge.
**Gunakan hanya pada VM/lab yang Anda kendalikan.** Jangan jalankan pada jaringan produksi tanpa izin.

## Cara pakai (aman)
1. Clone repo:
git clone https://github.com/USERNAME/snort-hids-setup.git
cd snort-hids-setup

markdown
Copy code
2. Periksa isi `setup-snort-hids.sh`.
3. Jalankan setelah memastikan:
sudo chmod +x setup-snort-hids.sh
sudo ./setup-snort-hids.sh

shell
Copy code

## Verifikasi
Sebelum menjalankan, periksa checksum:
sha256sum setup-snort-hids.sh

shell
Copy code

## Lisensi
MIT
Ganti USERNAME dengan akunmu.
