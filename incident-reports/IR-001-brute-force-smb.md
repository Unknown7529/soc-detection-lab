# IR-001: Brute Force SMB terhadap akun administrator

| Atribut | Nilai |
|---|---|
| Severity | High |
| Status | True positive (aktivitas simulasi lab) |
| Detection rule | SOC-001 Brute Force SMB |
| Host terdampak | Win10-SOC-LAB |
| Waktu deteksi | 2026-10-28 09:55:07 (WIB) |
| MITRE ATT&CK | T1110.001 Password Guessing |

## 1. Ringkasan

Akun `administrator` pada host `Win10-SOC-LAB` menerima rentetan login gagal lewat jaringan (SMB, Logon Type 3) dari `192.168.229.1`. Pola ini sesuai password guessing. Serangan disimulasikan dari laptop host menggunakan loop `net use`.

## 2. Alert yang memicu

SOC-001 Brute Force SMB (severity High), mendeteksi 10 atau lebih event 4625 dari satu IP sumber. Alert tercatat 09:55:07 untuk serangan yang dimulai 09:52. Bukti: [triggered alert](../detections/screenshots/soc-001-triggered-alert.png).

## 3. Timeline (WIB)

| Waktu | Sumber | Event | Bukti |
|---|---|---|---|
| 09:25:10 - 09:25:40 | Security 4625 | Sesi uji pertama: 15 login gagal, akun `administrator`, Logon Type 3 | [02-security-4625](../attack-simulation/brute-force/02-security-4625.png) |
| 09:52 - 09:53:10 | Security 4625 | Sesi kedua dari host yang sama, login gagal terakhir 09:53:10 | [01a](../attack-simulation/brute-force/01a-host-attack-command.png), [01b](../attack-simulation/brute-force/01b-host-attack-command.png) |
| 09:55:07 | Splunk alert | SOC-001 memicu, severity High | [triggered alert](../detections/screenshots/soc-001-triggered-alert.png) |

Total event 4625 dari IP yang sama tercatat 66 sejak 2026-10-27 11:38:28 (beberapa sesi uji).

## 4. Analisis

- **Sumber:** `192.168.229.1`, alamat laptop host di jaringan host-only (IP internal).
- **Target:** satu akun (`administrator`), bukan banyak akun, jadi pola password guessing pada satu akun.
- **Metode:** Logon Type 3 (jaringan), konsisten dengan SMB.
- **Kecepatan:** 15 percobaan dalam sekitar 30 detik (satu percobaan tiap 2 detik), terlalu teratur untuk manusia.
- **Alasan gagal:** lihat [03-failure-reason-4625](../attack-simulation/brute-force/03-failure-reason-4625.png) (kode Status/Sub_Status).
- **Logon sukses dari IP yang sama:** tidak ada ([bukti](../attack-simulation/brute-force/04-no-successful-logon-4624.png), [ringkasan](../attack-simulation/brute-force/05-brute-force-timeline.png)).
- **Kesimpulan:** true positive. Aktivitas ini simulasi lab, tetapi pola dan alurnya sama dengan serangan sungguhan.

## 5. IOC

| Jenis | Nilai |
|---|---|
| IP sumber | 192.168.229.1 |
| Akun target | administrator |
| Event | 4625, Logon Type 3 |
| Host | Win10-SOC-LAB |

## 6. Dampak

Tidak ada logon sukses (4624) dari IP penyerang, jadi tidak ada bukti akun berhasil diambil alih.

## 7. Rekomendasi

- Pada kejadian nyata: blokir IP sumber, dan pastikan kebijakan account lockout aktif.
- Tinjau paparan SMB dan batasi akses jaringan ke port 445.
- Pertimbangkan MFA dan password kuat untuk akun administratif.
- Eskalasi ke L2 jika ada logon sukses dari IP yang sama, atau jika sumber tidak dikenal dan eksternal.

## 8. Catatan

Waktu deteksi dipengaruhi jadwal cron 5 menit. Alert sempat memicu berulang tanpa serangan baru karena time range salah konfigurasi; perbaikan dicatat di [lessons-learned](../lessons-learned.md).
