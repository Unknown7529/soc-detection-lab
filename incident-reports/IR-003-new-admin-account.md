# IR-003: Akun lokal baru ditambahkan ke grup Administrators

| Atribut | Nilai |
|---|---|
| Severity | High |
| Status | True positive (aktivitas simulasi lab) |
| Detection rule | SOC-006 Member Added to Local Administrators |
| Host terdampak | Win10-SOC-LAB |
| Waktu kejadian | 2026-10-27 20:08:22 (WIB), Atomic Red Team T1136.001-8 |
| MITRE ATT&CK | T1136.001, T1098 |

> **Catatan penulis (hapus setelah diisi):** isi waktu trigger alert dan selisih deteksi dari [soc-006-triggered-alert.png](../detections/screenshots/soc-006-triggered-alert.png) di bagian 2 dan 3.

## 1. Ringkasan

Akun lokal `T1136.001_Admin` dibuat, lalu dimasukkan ke grup Users dan Administrators dalam hitungan milidetik. Pola "buat akun lalu langsung dijadikan admin" lazim dipakai penyerang untuk persistensi.

## 2. Alert yang memicu

SOC-006 Member Added to Local Administrators (High). Pada tes alert 2026-10-28, akun `SOC006Test` dan `SOC006Try` dibuat dan dijadikan admin. Waktu trigger: **ISI dari screenshot**. Bukti: [triggered alert](../detections/screenshots/soc-006-triggered-alert.png), [hasil](../detections/screenshots/soc-006-alert-results.png).

## 3. Timeline (WIB)

| Waktu | Sumber | Event | Bukti |
|---|---|---|---|
| 2026-10-27 20:08:22.579 | Security 4720 | Akun `T1136.001_Admin` dibuat (SID berakhiran -1002) | [04a-security-4720-raw](../attack-simulation/new-admin-account/04a-security-4720-raw.png) |
| 20:08:22.612 | Security 4732 | Ditambahkan ke grup Users | [04-security-4720-4732](../attack-simulation/new-admin-account/04-security-4720-4732.png) |
| 20:08:22.640 | Security 4732 | Ditambahkan ke grup Administrators (S-1-5-32-544) | [04b-security-4732-administrators](../attack-simulation/new-admin-account/04b-security-4732-administrators.png) |
| 2026-10-28 12:48 - 15:42 | Security 4720/4732 | Tes alert SOC-006 (`SOC006Test`, `SOC006Try`) | [soc-006-query-result](../detections/screenshots/soc-006-query-result.png) |

Timeline gabungan: [05-timeline-combined](../attack-simulation/new-admin-account/05-timeline-combined.png).

## 4. Analisis

- Pembuat akun adalah `WIN10-SOC-LAB` (Logon ID `0x81E7C`), akun pengguna lokal VM.
- Jarak antara pembuatan dan penambahan ke Administrators hanya sekitar 61 milidetik. Itu terlalu cepat untuk tindakan manual, dan menandakan skrip atau perintah berantai (`net user /add` diikuti `net localgroup administrators /add`).
- Akun baru tidak punya Display Name, dan password tidak pernah diubah (`<never>`), ciri akun yang dibuat sekilas.
- **False positive yang ditemui:** rule ini juga menangkap event setup Windows (`defaultuser0`, `WDAGUtilityAccount`, akun pengguna pertama). Pembeda: pembuat akun mesin (nama berakhiran `$`), nama host sementara (`DESKTOP-1LQT84G`), dan akun sementara sudah hilang setelah setup. Bukti: [soc-006-false-positive-oobe](../detections/screenshots/soc-006-false-positive-oobe.png).
- **Kesimpulan:** true positive untuk `T1136.001_Admin` dan akun uji SOC-006; event setup adalah false positive yang bisa dijelaskan.

## 5. IOC

| Jenis | Nilai |
|---|---|
| Akun baru | T1136.001_Admin (S-1-5-21-...-1002) |
| Akun uji | SOC006Test, SOC006Try |
| Grup | Administrators (S-1-5-32-544) |
| Event | 4720, 4732 |
| Pembuat | WIN10-SOC-LAB, Logon ID 0x81E7C |
| Host | Win10-SOC-LAB |

## 6. Dampak

Akun administrator tambahan berhasil dibuat pada host lab. Semua akun dihapus setelah pengujian: [cleanup Atomic](../attack-simulation/new-admin-account/06-cleanup-confirmed.png), [cleanup SOC-006](../detections/screenshots/soc-006-cleanup.png).

## 7. Rekomendasi

- Pada kejadian nyata: nonaktifkan dan hapus akun, reset kredensial pembuat jika akunnya dicurigai, dan telusuri aktivitas akun tersebut (logon 4624).
- Cocokkan dengan tiket perubahan sebelum eskalasi.
- Batasi siapa yang boleh menambah anggota ke grup Administrators dan pantau grup itu secara berkelanjutan.
- Eskalasi ke L2 jika tidak ada tiket atau akun tidak dikenal.
