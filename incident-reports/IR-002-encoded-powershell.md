# IR-002: Eksekusi PowerShell ter-encode dan ter-obfuscate

| Atribut | Nilai |
|---|---|
| Severity | High |
| Status | True positive (aktivitas simulasi lab) |
| Detection rule | SOC-003 Encoded PowerShell Command |
| Host terdampak | Win10-SOC-LAB |
| Waktu kejadian | 2026-10-27 19:37:17 (WIB), Atomic Red Team T1059.001-17 |
| MITRE ATT&CK | T1059.001, T1027 |

## 1. Ringkasan

`powershell.exe` dijalankan dengan parameter `-e` dan string base64 panjang, dengan parent `cmd.exe`. Setelah di-decode, perintahnya menampilkan teks (jinak), tetapi disamarkan dengan teknik obfuscation yang lazim dipakai malware.

## 2. Alert yang memicu

SOC-003 Encoded PowerShell Command (High). Pada tes alert terpisah (perintah ter-encode sederhana, 2026-10-28 11:00:05), alert tercatat 11:09:27, sekitar 9 menit. Bukti: [triggered alert](../detections/screenshots/soc-003-triggered-alert.png), [hasil](../detections/screenshots/soc-003-alert-results.png).

## 3. Timeline (WIB)

| Waktu | Sumber | Event | Bukti |
|---|---|---|---|
| 2026-10-27 19:37:17 | Sysmon 1 | `powershell.exe -e JgAgACgAZwBjAG0A...`, parent `cmd.exe`, user `WIN10-SOC-LAB\WIN10-SOC-LAB` | [03-sysmon-event1](../attack-simulation/powershell-encoded/03-sysmon-event1.png) |
| sama | PowerShell 4104 | Script block menunjukkan isi perintah setelah di-decode | [04-powershell-4104](../attack-simulation/powershell-encoded/04-powershell-4104.png) |
| 2026-10-28 11:00:05 | Sysmon 1 | Tes alert (perintah ter-encode sederhana) | [soc-003-query-result](../detections/screenshots/soc-003-query-result.png) |
| 2026-10-28 11:09:27 | Splunk alert | SOC-003 memicu | [triggered alert](../detections/screenshots/soc-003-triggered-alert.png) |

## 4. Analisis

String base64 di-decode (UTF-16LE) menjadi:

```
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

Cara membacanya:
1. `('ie{0}' -f 'x')` merakit string `iex` (alias `Invoke-Expression`).
2. `gcm` (`Get-Command`) dipakai untuk memanggil `iex` secara tidak langsung.
3. String perintah dipecah-pecah lalu digabung dengan `+` agar tidak terdeteksi pencarian kata kunci.
4. Hasil akhirnya hanya `Write-Host 'Hello, from PowerShell!'`.

Bukti decode: [05-decoded-command](../attack-simulation/powershell-encoded/05-decoded-command.png).

Penilaian: payload akhir jinak, tetapi kombinasi `-EncodedCommand`, pemanggilan `iex` tidak langsung, dan pemecahan string tidak lazim untuk aktivitas administrator. Klasifikasi true positive, severity High karena tekniknya menyembunyikan niat. Dalam lingkungan nyata, payload lain dengan teknik yang sama bisa mengunduh atau menjalankan malware.

False positive yang pernah ditemui pada rule ini: `CompatTelRunner.exe` (telemetri Windows) memakai `-ExecutionPolicy`, bukan `-EncodedCommand`. Ditangani dengan regex yang mewajibkan spasi setelah parameter ([contoh](../detections/screenshots/soc-003-false-positive-example.png)).

## 5. IOC

| Jenis | Nilai |
|---|---|
| Proses | powershell.exe |
| Parent | C:\Windows\System32\cmd.exe |
| Parameter | -e (EncodedCommand) |
| Awal string base64 | JgAgACgAZwBjAG0A... |
| Teknik | iex via gcm, string dipecah |
| Akun | WIN10-SOC-LAB\WIN10-SOC-LAB |

## 6. Dampak

Tidak ada dampak, karena payload hanya mencetak teks.

## 7. Rekomendasi

- Pada kejadian nyata: cek proses anak, koneksi jaringan, dan file baru dari proses ini; isolasi host jika ada aktivitas lanjutan.
- Aktifkan PowerShell Script Block Logging (sudah aktif di lab) dan Constrained Language Mode di endpoint yang sesuai.
- Eskalasi ke L2 jika isi decode mengunduh file atau parent tidak wajar.
- Tambahkan rule SOC-004 untuk obfuscation di script block.

## 8. Catatan

Waktu deteksi sekitar 9 menit dipengaruhi jadwal cron 5 menit dan jeda pengiriman log.
