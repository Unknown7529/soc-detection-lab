# SOC-003: Encoded PowerShell Command

| Atribut | Nilai |
|---|---|
| Severity | High |
| MITRE ATT&CK | T1059.001 (PowerShell), T1027 (Obfuscated Files or Information) |
| Tactic | Execution, Defense Evasion |
| Sumber log | Sysmon EventCode 1 (Process Create) |
| Jadwal | Setiap 5 menit, jendela 15 menit |
| Trigger | Number of Results > 0, mode Once |
| Throttle | 15 menit |
| Expires | 7 hari |

## Logika

`powershell.exe` dijalankan dengan parameter `-e`, `-enc`, atau `-EncodedCommand`. Regex mewajibkan spasi sebelum dan sesudah parameter, supaya `-ExecutionPolicy` tidak ikut cocok. String base64 diekstrak ke field `b64` agar analis bisa langsung men-decode.

## Query

```
index=lab_soc source=*Sysmon* EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)\s-(e|ec|en|enc|enco\w*|encodedcommand)\s"
| rex field=CommandLine "(?i)\s-(?:e|ec|en|enc|enco\w*|encodedcommand)\s+(?<b64>[A-Za-z0-9+/=]+)"
| table _time, host, User, ParentImage, CommandLine, b64
```

## Validasi

- Atomic Red Team T1059.001-17 menghasilkan event 2026-10-27 19:37:17, parent `cmd.exe`.
- Tes alert: perintah ter-encode sederhana dijalankan 2026-10-28 11:00:05, alert tercatat 11:09:27 (sekitar 9 menit).
- Bukti: [query](screenshots/soc-003-query-result.png), [triggered alert](screenshots/soc-003-triggered-alert.png), [hasil alert](screenshots/soc-003-alert-result.png), [konfigurasi](screenshots/soc-003-alert-config.png).

## Contoh analisis

String base64 dari Atomic test di-decode (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("..."))`) menjadi:

```
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

Artinya `Write-Host 'Hello, from PowerShell!'`, jadi payload jinak. Tetapi teknik pembungkusnya (string dipecah, `iex` dirakit lewat `-f`, dipanggil lewat `gcm`, ditambah base64) lazim pada malware. Bukti: [decode](../attack-simulation/powershell-encoded/05-decoded-command.png).

## False positive

- Tool manajemen (SCCM, Intune, skrip deployment) yang memakai encoding.
- Skrip admin yang di-encode untuk menangani karakter khusus.
- Installer software.
- Query yang terlalu longgar (`-e*`) menangkap `CompatTelRunner.exe` (telemetri Windows, akun SYSTEM) yang memakai `-ExecutionPolicy`. Lihat [contoh](screenshots/soc-003-false-positive-example.png). Regex ketat di atas sudah mengatasinya.

## Tuning

- Kecualikan `ParentImage` dan akun yang dikenal sah.
- Tambahkan filter panjang string base64.
- Tambahkan rule terpisah untuk `iex` atau `Invoke-Expression` di script block (rencana SOC-004).

## Respons L1

1. Decode string base64 dan baca isinya.
2. Cek `ParentImage` dan `User`: siapa dan dari proses apa.
3. Cek apakah ada aktivitas lanjutan (koneksi jaringan, proses anak, file baru).
4. Eskalasi ke L2 jika isinya mengunduh file, memakai `Invoke-Expression`, atau parent tidak wajar.
