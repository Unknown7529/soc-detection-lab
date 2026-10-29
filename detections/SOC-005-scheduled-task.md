# SOC-005: Scheduled Task Created via schtasks

| Atribut | Nilai |
|---|---|
| Severity | Medium |
| MITRE ATT&CK | T1053.005 (Scheduled Task/Job: Scheduled Task) |
| Tactic | Persistence, Execution, Privilege Escalation |
| Sumber log | Sysmon EventCode 1 (Process Create) |
| Jadwal | Setiap 5 menit, jendela 15 menit |
| Trigger | Number of Results > 0, mode Once |
| Throttle | 15 menit |
| Expires | 7 hari |

## Logika

`schtasks.exe` dijalankan dengan parameter `/create`.

## Query

```
index=lab_soc source=*Sysmon* EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| table _time, host, User, ParentImage, CommandLine
```

## Validasi

- Atomic Red Team T1053.005-2: `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`, parent `cmd.exe`. Sysmon 1 dan Security 4698 tercatat selisih sekitar 37 milidetik.
- Tes alert: `schtasks /create /tn SOC005Test ...` dijalankan 2026-10-28 11:51:11, alert tercatat 11:59:17 (sekitar 8 menit). Trigger kedua pada 12:04:17 berasal dari event yang sama karena jendela 15 menit melewati beberapa eksekusi jadwal.
- Bukti: [query](screenshots/soc-005-query-result.png), [triggered alert](screenshots/soc-005-triggered-alert.png), [hasil](screenshots/soc-005-alert-result.png), [konfigurasi](screenshots/soc-005-alert-config.png), [cleanup](screenshots/soc-005-cleanup.png).

## False positive

- Installer dan updater software (browser, Office, driver).
- Skrip admin dan agen manajemen.

## Tuning

- Kecualikan `ParentImage` dan `User` yang dikenal sah.
- Beri prioritas lebih tinggi jika `/TR` menjalankan `cmd.exe`, `powershell.exe`, atau file di folder Temp/AppData.
- Pastikan throttle aktif agar event yang sama tidak memicu trigger ganda.

## Keterbatasan

Rule berbasis `schtasks.exe` tidak menangkap task yang dibuat lewat API (`Register-ScheduledTask`, COM, atau WMI) karena tidak melewati `schtasks.exe`. Event Security 4698 mencatat pembuatan task dari cara apa pun, tetapi berisik karena Windows sendiri membuat banyak task. Rencana: rule 4698 dengan filter task bawaan Microsoft.

## Respons L1

1. Baca `/TR` (apa yang dijalankan), `/SC` dan `/ST` (jadwal).
2. Cek `ParentImage` dan `User`: apakah wajar membuat task.
3. Cek 4698 untuk isi task lengkap.
4. Eskalasi ke L2 jika `/TR` menunjuk ke shell, file di folder user/Temp, atau pembuatnya tidak dikenal.
